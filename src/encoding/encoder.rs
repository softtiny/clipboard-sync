use std::cmp::min;
use std::ops::Sub;
use std::pin::Pin;
use std::task::{Context, Poll};

use aead::generic_array::ArrayLength;
use aead::stream::{Encryptor, NewStream, Nonce, NonceSize, StreamPrimitive};
use aead::{AeadInPlace, Tag};
use chacha20poly1305::aead::NewAead;
use futures_core::ready;
use pin_project::pin_project;
use tokio::io::AsyncWrite;

#[pin_project]
struct EncryptionEncoder<W, A, S>
where
    W: AsyncWrite,
    A: AeadInPlace,
    S: StreamPrimitive<A>,
    A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    encryptor: Option<Encryptor<A, S>>,
    nonce: Option<Nonce<A, S>>,
    #[pin]
    writer: W,
    encrypted_buffer: Vec<u8>,
    data_buffer: Vec<u8>,
    frame_size: usize,
}

impl<W, A, S> EncryptionEncoder<W, A, S>
where
    W: AsyncWrite,
    A: AeadInPlace,
    S: StreamPrimitive<A>,
    A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    pub fn new(cipher: A, nonce: Nonce<A, S>, writer: W, capacity: usize, frame_size: usize) -> Self
    where
        A: NewAead,
        S: NewStream<A>,
    {
        Self {
            encryptor: Some(Encryptor::<A, S>::from_aead(cipher, &nonce)),
            writer,
            encrypted_buffer: Vec::with_capacity(capacity),
            data_buffer: Vec::with_capacity(capacity),
            frame_size,
            nonce: Some(nonce),
        }
    }

    pub fn as_inner(&self) -> &W
    {
        &self.writer
    }
}

impl<W, A, S> AsyncWrite for EncryptionEncoder<W, A, S>
where
    W: AsyncWrite,
    A: AeadInPlace,
    S: StreamPrimitive<A>,
    A::NonceSize: Sub<<S as StreamPrimitive<A>>::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>>
    {
        let this = self.project();
        this.data_buffer.extend_from_slice(buf);
        let max_data_frame_size = *this.frame_size - std::mem::size_of::<Tag<A>>();
        if this.nonce.is_some() {
            let nonce = this.nonce.take().unwrap();
            this.encrypted_buffer.extend_from_slice(nonce.as_slice());
        }
        while this.data_buffer.len() >= max_data_frame_size
            && buf.len() >= (this.encrypted_buffer.len() + *this.frame_size)
        {
            let data = this.data_buffer.drain(..max_data_frame_size);
            let encrypted_block = this
                .encryptor
                .as_mut()
                .unwrap()
                .encrypt_next(data.as_slice())
                .unwrap();

            this.encrypted_buffer.extend(encrypted_block);
        }
        if this.encrypted_buffer.len() > 0 {
            let len_to_write = min(this.encrypted_buffer.len(), buf.len());
            ready!(this
                .writer
                .poll_write(cx, this.encrypted_buffer.drain(..len_to_write).as_slice()))?;

            return Poll::Ready(Ok(len_to_write));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>>
    {
        let this = self.project();
        if this.data_buffer.len() == 0 && this.encrypted_buffer.len() == 0 {
            return this.writer.poll_flush(cx);
        }
        let max_data_frame_size = *this.frame_size - std::mem::size_of::<Tag<A>>();
        while this.data_buffer.len() > max_data_frame_size {
            let data = this.data_buffer.drain(..max_data_frame_size);
            let encrypted_block = this
                .encryptor
                .as_mut()
                .unwrap()
                .encrypt_next(data.as_slice())
                .unwrap();

            this.encrypted_buffer.extend(encrypted_block);
        }
        let last_encrypted_block = this
            .encryptor
            .take()
            .unwrap()
            .encrypt_last(this.data_buffer.drain(..).as_slice())
            .unwrap();

        this.encrypted_buffer.extend(last_encrypted_block);

        match this
            .writer
            .poll_write(cx, this.encrypted_buffer.drain(..).as_slice())
        {
            Poll::Pending => Poll::Pending,
            _ => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>)
        -> Poll<Result<(), std::io::Error>>
    {
        let this = self.project();
        this.writer.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests
{
    use std::io::Cursor;

    use aead::stream::StreamBE32;
    use chacha20poly1305::{Key, XChaCha20Poly1305};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn test_encryption()
    {
        let expected = [
            117, 110, 105, 113, 117, 101, 32, 108, 111, 110, 103, 32, 116, 111, 107, 101, 110, 32,
            119, 124, 220, 76, 150, 227, 160, 232, 123, 132, 44, 43, 52, 190, 16, 121, 81, 9, 241,
            212, 253, 231, 147, 34, 146, 108, 123, 234, 179, 112, 244, 44, 252, 238, 18, 156, 250,
            64, 132, 125, 89, 139, 35, 236, 45, 150, 180, 216, 51, 15, 231, 199, 33, 12, 79, 93,
            72, 212, 36, 15, 139, 242, 181, 194, 202, 87, 76, 101, 117, 100, 151, 74, 136, 119, 18,
            113, 87, 183, 18, 229, 185, 64, 117, 245, 155, 154, 216, 28, 63, 139, 116, 170, 181,
            236, 222, 226, 24, 23,
        ];
        let key = Key::from_slice(b"an example very very secret key.");
        let cipher = XChaCha20Poly1305::new(key);
        let nonce_enc = Nonce::<XChaCha20Poly1305, StreamBE32<XChaCha20Poly1305>>::from_slice(
            b"unique long token w",
        )
        .to_owned();

        let existing_data = b"text to encrypt 32 bytes long st text to encrypt 32 bytes long ss";
        let mut data = Cursor::new(existing_data);
        let mut buffer = [0; 50];

        let writer = Vec::new();
        let mut encoder = EncryptionEncoder::<_, _, StreamBE32<XChaCha20Poly1305>>::new(
            cipher.clone(),
            nonce_enc,
            writer,
            50,
            50,
        );
        loop {
            match data.read(&mut buffer).await {
                Ok(read) if read > 0 => encoder.write(&buffer[..read]).await.unwrap(),
                _ => break,
            };
        }
        encoder.flush().await.unwrap();
        // println!("encoded {:?}", encoder.as_inner());
        assert_eq!(expected[..], encoder.as_inner()[..]);
    }
}
