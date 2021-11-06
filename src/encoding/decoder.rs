use std::cmp::min;
use std::ops::Sub;
use std::pin::Pin;
use std::task::{Context, Poll};

use aead::generic_array::ArrayLength;
use aead::stream::{Decryptor, NewStream, Nonce, NonceSize, StreamPrimitive};
use aead::{AeadInPlace, NewAead};
use futures_core::ready;
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

#[pin_project]
struct EncryptionDecoder<R, A, S>
where
    R: AsyncRead,
    A: AeadInPlace + Clone,
    S: StreamPrimitive<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    decryptor: Option<Decryptor<A, S>>,
    #[pin]
    reader: R,
    data_buffer: Vec<u8>,
    decrypted_buffer: Vec<u8>,
    frame_size: usize,
    cipher: A,
}

impl<R, A, S> EncryptionDecoder<R, A, S>
where
    R: AsyncRead,
    A: AeadInPlace + Clone,
    S: StreamPrimitive<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    pub fn new(cipher: A, reader: R, capacity: usize, frame_size: usize) -> Self
    {
        Self {
            decryptor: None,
            reader,
            data_buffer: Vec::with_capacity(capacity),
            decrypted_buffer: Vec::with_capacity(capacity),
            frame_size,
            cipher,
        }
    }
}

impl<R, A, S> AsyncRead for EncryptionDecoder<R, A, S>
where
    R: AsyncRead,
    A: AeadInPlace + Clone + NewAead,
    S: StreamPrimitive<A> + NewStream<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    NonceSize<A, S>: ArrayLength<u8>,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>>
    {
        let this = self.project();
        ready!(this.reader.poll_read(cx, buf))?;

        let slice = if this.decryptor.is_none()
            && buf.filled().len() >= std::mem::size_of::<Nonce<A, S>>()
        {
            let cd = &buf.filled()[..std::mem::size_of::<Nonce<A, S>>()];
            let _ = this.decryptor.insert(Decryptor::from_aead(
                this.cipher.clone(),
                Nonce::<A, S>::from_slice(cd),
            ));
            &buf.filled()[std::mem::size_of::<Nonce<A, S>>()..]
        } else {
            buf.filled()
        };
        if slice.len() == 0 {
            if this.data_buffer.len() > 0 {
                let decrypted = this
                    .decryptor
                    .take()
                    .unwrap()
                    .decrypt_last(this.data_buffer.drain(..this.data_buffer.len()).as_slice())
                    .unwrap();
                this.decrypted_buffer.extend(decrypted);
            } else {
                return Poll::Ready(Ok(()));
            }
        } else {
            this.data_buffer.extend_from_slice(slice);
            buf.clear();
        }

        if this.data_buffer.len() < *this.frame_size {
            if this.decrypted_buffer.len() > 0 {
                buf.put_slice(
                    this.decrypted_buffer
                        .drain(..min(buf.capacity(), this.decrypted_buffer.len()))
                        .as_slice(),
                );
                return Poll::Ready(Ok(()));
            }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let decrypted = this
            .decryptor
            .as_mut()
            .unwrap()
            .decrypt_next(this.data_buffer.drain(..*this.frame_size).as_slice())
            .unwrap();
        this.decrypted_buffer.extend(decrypted);
        buf.put_slice(
            this.decrypted_buffer
                .drain(..min(buf.capacity(), this.decrypted_buffer.len()))
                .as_slice(),
        );
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests
{
    use std::io::Cursor;

    use aead::stream::StreamBE32;
    use chacha20poly1305::{Key, XChaCha20Poly1305};

    use super::*;

    #[tokio::test]
    async fn test_decode()
    {
        let expected_data = b"text to encrypt 32 bytes long st text to encrypt 32 bytes long ss";
        let encrypted_data = [
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
        let reader = Cursor::new(encrypted_data);
        let mut decoder =
            EncryptionDecoder::<_, _, StreamBE32<XChaCha20Poly1305>>::new(cipher, reader, 100, 50);
        let mut decrypted = Vec::new();
        let mut buffer = [0; 40];
        loop {
            match decoder.read(&mut buffer).await {
                Ok(read) if read > 0 => decrypted.extend_from_slice(&buffer[..read]),
                _ => break,
            };
        }
        assert_eq!(expected_data[..], decrypted[..]);
    }
}
