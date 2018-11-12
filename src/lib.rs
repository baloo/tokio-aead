#![cfg_attr(feature = "cargo-clippy", deny(clippy::pedantic))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::cast_possible_truncation))]
#[macro_use] extern crate log;
extern crate futures;
extern crate bytes;
extern crate rand;
extern crate chacha20_poly1305_aead;

use std::mem;
use std::io;
use std::io::Write;

use bytes::{Bytes, BytesMut, BufMut, BigEndian, ByteOrder};
use futures::{Stream, Async};

mod buf;

use buf::{List as BufList, Error as BufError};

static MAGIC: [u8; 16] = [
    0xa, 0xe, 0xa, 0xd,
    0xa, 0xe, 0xa, 0xd,
    0xa, 0xe, 0xa, 0xd,
    0xa, 0xe, 0xa, 0xd
];
static CURRENT_VERSION: u32 = 1;

type Nonce = u64;
type Key = [u8; 32];

pub struct AEAD {
    key: Key,
    blocksize: usize,
}

impl AEAD {
    pub fn new(key: &[u8], blocksize: usize) -> Self {
        assert!(key.len() == 32);
        assert!(blocksize % 4096 == 0);
        assert!(blocksize <= ((2_usize.pow(32) - 1) * 64));

        let mut owned_key = [0_u8; 32];
        owned_key.copy_from_slice(key);

        Self {
            key: owned_key,
            blocksize,
        }
    }

    pub fn encrypt<T>(&self, inner: T) -> Encrypting<T> {
        Encrypting {
            key: self.key,
            blocksize: self.blocksize,
            state: EncryptingState::Uninitialized {
               // rand::random is a shortcut for thread_rng().gen()
               // and thread_rng is documented as cryptographically secure PRNG
               // but I'm no cryptographer, use at your own risks
                nonce: rand::random(),
            },
            inner,
        }
    }

    pub fn decrypt<T, Payload, E>(&self, inner: T) -> Decrypting<T, Payload>
        where T: Stream<Item=Payload, Error=E> {
        Decrypting {
            key: self.key,
            state: DecryptingState::Start {
                buf: BufList::new()
            },
            inner,
        }
    }
}

#[derive(Debug)]
pub enum Error<E> {
    Underlying(E),
    InvalidState,
    InvalidPayload,
    Authentication,
    VersionNotSupported,
    IO(io::Error),
}

impl<E> From<io::Error> for Error<E> {
    fn from(e: io::Error) -> Self {
        Error::IO(e)
    }
}

impl<E> PartialEq for Error<E>
    where E: PartialEq {

    fn eq(&self, oth: &Self) -> bool {
        match (self, oth) {
            (Error::Underlying(ref my), Error::Underlying(ref o)) if my.eq(o) => true,
            (Error::InvalidState, Error::InvalidState) |
            (Error::InvalidPayload, Error::InvalidPayload) |
            (Error::Authentication, Error::Authentication) |
            (Error::VersionNotSupported, Error::VersionNotSupported) => true,
            (Error::IO(ref my), Error::IO(ref oth)) if my.kind().eq(&oth.kind()) => true,
            _ => false,
        }
    }
}

enum EncryptingState {
    Working,
    Uninitialized{nonce: Nonce},
    Reading{nonce: Nonce, aad: [u8; 16], buf: BytesMut},
    EOF,
}

pub struct Encrypting<T> {
    key: Key,
    blocksize: usize,
    state: EncryptingState,
    inner: T,
}

impl<T, Payload, E> Stream for Encrypting<T>
    where T: Stream<Item=Payload, Error=E>,
          Payload: AsRef<[u8]> {
    type Item=Bytes;
    type Error=Error<E>;

    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
        loop {
            match mem::replace(&mut self.state, EncryptingState::Working) {
                EncryptingState::Working => {
                    return Err(Error::InvalidState)
                },
                EncryptingState::Uninitialized{nonce} => {
                    let mut buf = BytesMut::with_capacity(4);
                    buf.put_slice(&MAGIC);
                    buf.put_u32_be(CURRENT_VERSION);
                    let aad = MAGIC;

                    mem::replace(&mut self.state, EncryptingState::Reading{
                        nonce,
                        buf,
                        aad,
                    });
                },
                EncryptingState::Reading{mut nonce, mut buf, aad} => {
                    match self.inner.poll().map_err(Error::Underlying)? {
                        Async::NotReady => {
                            mem::replace(&mut self.state, EncryptingState::Reading{
                                nonce,
                                buf,
                                aad
                            });
                            return Ok(Async::NotReady)
                        },

                        Async::Ready(None) => {
                            mem::replace(&mut self.state, EncryptingState::EOF);
                            continue;
                        },

                        Async::Ready(Some(ref cleartext_buf)) => {
                            let cleartext_buf: &[u8] = cleartext_buf.as_ref();
                            let full_blocks = cleartext_buf.len() / self.blocksize;
                            let mut newsize = full_blocks * (
                                4 + // block len
                                12 + // nonce
                                self.blocksize +
                                16 // block signature
                            );
                            if cleartext_buf.len() % self.blocksize != 0 {
                                // We have an incomplete block
                                newsize +=
                                    4 + // block len
                                    12 + // nonce
                                    cleartext_buf.len() % self.blocksize +
                                    16; // block signature
                            }

                            // Make room for new data
                            buf.reserve(newsize);

                            let mut res: [u8; 16] = aad;
                            let mut writer = buf.writer();
                            trace!("cleartext buffer len {}", cleartext_buf.len());
                            for input in cleartext_buf.chunks(self.blocksize) {
                                let mut len_slice = [0_u8; 4];

                                BigEndian::write_u32(&mut len_slice, input.len() as u32);
                                writer.write_all(&len_slice)?;

                                let mut nonce_slice = [0_u8; 12];
                                BigEndian::write_u64(&mut nonce_slice, nonce);
                                writer.write_all(&nonce_slice)?;

                                trace!("encrypting block input len {} output len {}", input.len(), writer.get_ref().len());
                                res = chacha20_poly1305_aead::encrypt(&self.key, &nonce_slice, &res, input, &mut writer)?;
                                trace!("output len {} after", writer.get_ref().len());
                                trace!("ciphering nonce: {:?} tag: {:?}", nonce_slice, res);

                                // Nonce shouldn't be reused, but we can handle
                                // them as counter. Just do that
                                nonce += 1;

                                writer.write_all(&res)?;
                            }
                            let buf = writer.into_inner();

                            // We have now encrypted our block, we will feed
                            // last tag as AAD for next block
                            mem::replace(&mut self.state, EncryptingState::Reading{
                                nonce,
                                buf: BytesMut::new(),
                                aad: res,
                            });

                            let buf = buf.freeze();

                            trace!("output buffer len {}", buf.len());

                            return Ok(Async::Ready(Some(buf)));
                        }
                    }
                },
                EncryptingState::EOF => {
                    mem::replace(&mut self.state, EncryptingState::EOF);
                    return Ok(Async::Ready(None));
                }
            }
        }
    }
}

enum DecryptingState<Payload> {
    Working,
    Start{buf: BufList<Payload>},
    GotMagic{buf: BufList<Payload>},
    ReadingV1{buf: BufList<Payload>, state: Version1},
    EOF,
}

pub struct Decrypting<T, Payload> {
    key: Key,
    state: DecryptingState<Payload>,
    inner: T
}

impl<T, Payload, E> Stream for Decrypting<T, Payload>
    where T: Stream<Item=Payload, Error=E>,
          Payload: AsRef<[u8]> {
    type Item=Bytes;
    type Error=Error<E>;

    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
        loop {
            match mem::replace(&mut self.state, DecryptingState::Working) {
                DecryptingState::Working => {
                    return Err(Error::InvalidState)
                },
                DecryptingState::Start{mut buf} => {
                    match self.inner.poll().map_err(Error::Underlying)? {
                        Async::NotReady => {
                            mem::replace(&mut self.state, DecryptingState::Start{
                                buf
                            });
                            return Ok(Async::NotReady);
                        },
                        Async::Ready(None) => {
                            return Err(Error::InvalidPayload)
                        },
                        Async::Ready(Some(new_payload)) => {
                            buf.push(new_payload);

                            let mut buf = buf.reader();

                            let mut expect_magic = [0_u8; 16];
                            match buf.read(&mut expect_magic) {
                                Err(BufError::NoEnoughBytes) => {
                                    let buf = buf.get_inner();
                                    mem::replace(&mut self.state, DecryptingState::Start{
                                        buf
                                    });
                                    return Ok(Async::NotReady);
                                },
                                Ok(_) if expect_magic == MAGIC => {
                                },
                                _ => {
                                    return Err(Error::InvalidPayload);
                                }
                            }

                            let buf = buf.get_inner();

                            mem::replace(&mut self.state, DecryptingState::GotMagic{
                                buf
                            });
                        }
                    }
                },
                DecryptingState::GotMagic{buf} => {
                    let mut buf = buf.reader();
                    match buf.read_u32_be() {
                        Ok(version) if version > CURRENT_VERSION || version == 0 => {
                            return Err(Error::VersionNotSupported)
                        },
                        Ok(version) if version == 1 => {
                            let buf = buf.get_inner();

                            mem::replace(&mut self.state, DecryptingState::ReadingV1 {
                                buf,
                                state: Version1::new(self.key)
                            });
                            continue;
                        },
                        Ok(_) => {
                            return Err(Error::VersionNotSupported)
                        },
                        Err(BufError::NoEnoughBytes) => {
                            let mut buf = buf.get_inner();
                            match self.inner.poll().map_err(Error::Underlying)? {
                                Async::NotReady => {
                                    mem::replace(&mut self.state, DecryptingState::GotMagic {
                                        buf
                                    });
                                    return Ok(Async::NotReady);
                                },
                                Async::Ready(None) => {
                                    return Err(Error::InvalidPayload)
                                },
                                Async::Ready(Some(new_payload)) => {
                                    buf.push(new_payload);

                                    mem::replace(&mut self.state, DecryptingState::GotMagic {
                                        buf
                                    });
                                    continue;
                                }
                            }
                        }
                    }
                },
                DecryptingState::ReadingV1 {buf, state} => {
                    match state.poll(buf) {
                        // There was complete block in buf
                        (state, buf, Ok(Some(cleartext))) => {
                            mem::replace(&mut self.state, DecryptingState::ReadingV1 {
                                buf,
                                state
                            });
                            return Ok(Async::Ready(Some(cleartext)));
                        },
                        // There is no block in buf
                        (state, mut buf, Ok(None)) => {
                            // It's a good time to check underlying stream
                            // it might be an EOF
                            match self.inner.poll().map_err(Error::Underlying)? {
                                Async::NotReady => {
                                    mem::replace(&mut self.state, DecryptingState::ReadingV1 {
                                        buf,
                                        state
                                    });
                                    return Ok(Async::NotReady);
                                },
                                Async::Ready(None) => {
                                    mem::replace(&mut self.state, DecryptingState::EOF);
                                    continue;
                                },
                                Async::Ready(Some(payload)) => {
                                    buf.push(payload);

                                    mem::replace(&mut self.state, DecryptingState::ReadingV1 {
                                        buf,
                                        state
                                    });
                                    continue;
                                }
                            }

                        },
                        (state, mut buf, Err(V1Error::Control(BufError::NoEnoughBytes))) => {
                            match self.inner.poll().map_err(Error::Underlying)? {
                                Async::NotReady => {
                                    return Ok(Async::NotReady);
                                },
                                Async::Ready(None) => {
                                    return Err(Error::InvalidState);
                                },
                                Async::Ready(Some(payload)) => {
                                    buf.push(payload);
                                    mem::replace(&mut self.state, DecryptingState::ReadingV1 {
                                        buf,
                                        state
                                    });
                                    continue;
                                }
                            }
                        }
                        (_, _, Err(V1Error::TagMismatch)) => {
                            return Err(Error::Authentication);
                        }
                        (_, _, Err(V1Error::InvalidState)) => {
                            return Err(Error::InvalidState);
                        }
                    }
                }
                DecryptingState::EOF => {
                    mem::replace(&mut self.state, DecryptingState::EOF);
                    return Ok(Async::Ready(None));
                }

            }
        }
    }
}

enum V1Error {
    Control(BufError),
    TagMismatch,
    InvalidState,
}

struct Version1{
    key: Key,
    state: V1State
}

#[derive(Debug)]
enum V1State {
    Start,
    ReadingNextBlock {
        aad: [u8; 16],
    },
    ReadingNonce {
        aad: [u8; 16],
        length: usize,
    },
    ReadingData {
        aad: [u8; 16],
        nonce: [u8; 12],
        ciphertext_buffer: BytesMut,
        length: usize,
    },
    ReadingTag {
        aad: [u8; 16],
        nonce: [u8; 12],
        ciphertext_buffer: BytesMut,
        length: usize,
    },
    Errored,
    Working,

}

impl Version1 {
    fn new(key: Key) -> Self {
        Self {
            key,
            state: V1State::Start
        }
    }

    fn poll<Payload>(mut self, data: BufList<Payload>) -> (Self, BufList<Payload>, Result<Option<Bytes>, V1Error>)
        where Payload: AsRef<[u8]> {

        let mut reader = data.reader();

        loop {
            match mem::replace(&mut self.state, V1State::Working) {
                V1State::Working => {
                    let buf = reader.get_inner();
                    return (self, buf, Err(V1Error::InvalidState))
                },
                V1State::Errored => {
                    let buf = reader.get_inner();
                    return (self, buf, Err(V1Error::TagMismatch))
                }
                V1State::Start => {
                    mem::replace(&mut self.state, V1State::ReadingNextBlock {
                       aad: MAGIC,
                    });
                    continue;
                },
                V1State::ReadingNextBlock {aad} => {
                    if reader.remaining() == 0 {
                        mem::replace(&mut self.state, V1State::ReadingNextBlock {
                           aad,
                        });
                        let buf = reader.get_inner();
                        return (self, buf, Ok(None));
                    }
                    match reader.read_u32_be() {
                        Err(e) => {
                            mem::replace(&mut self.state, V1State::ReadingNextBlock {
                               aad,
                            });
                            let buf = reader.get_inner();
                            return (self, buf, Err(V1Error::Control(e)))
                        }
                        Ok(length) => {
                            let length = length as usize;
                            mem::replace(&mut self.state, V1State::ReadingNonce {
                               aad,
                               length,
                            });
                            continue;
                        }
                    }
                },
                V1State::ReadingNonce {aad, length} => {
                    let mut nonce = [0_u8; 12];
                    if let Err(e) = reader.read(&mut nonce) {
                        let buf = reader.get_inner();
                        return (self, buf, Err(V1Error::Control(e)))
                    } else {
                        // TODO: Because we allocate here and input is not
                        // yet checked, we might DoS our reader (by feeding
                        // it invalid data). We should put hard limits on
                        // block size (4MB?) but I'm not quite sure which
                        // limit is sane
                        let mut ciphertext_buffer = BytesMut::with_capacity(length);
                        ciphertext_buffer.resize(length, 0);
                        mem::replace(&mut self.state, V1State::ReadingData {
                           aad,
                           nonce,
                           ciphertext_buffer,
                           length,
                        });
                        continue;
                    }
                },
                V1State::ReadingData{aad, nonce, mut ciphertext_buffer, length} => {
                    trace!("reading {} bytes of ciphertext", length);
                    if let Err(e) = reader.read(ciphertext_buffer.as_mut()) {
                        let buf = reader.get_inner();
                        return (self, buf, Err(V1Error::Control(e)))
                    } else {
                        mem::replace(&mut self.state, V1State::ReadingTag {
                           aad,
                           nonce,
                           ciphertext_buffer,
                           length,
                        });
                        continue;
                    }
                },
                V1State::ReadingTag{aad, nonce, ciphertext_buffer, length} => {
                    let mut tag = [0_u8; 16];
                    if let Err(e) = reader.read(&mut tag) {
                        let buf = reader.get_inner();
                        return (self, buf, Err(V1Error::Control(e)))
                    } else {
                        let buf = reader.get_inner();
                        let cleartext_buffer = BytesMut::with_capacity(length);
                        let mut writer = cleartext_buffer.writer();
                        trace!("deciphering nonce: {:?} tag: {:?}", nonce, tag);
                        let res = chacha20_poly1305_aead::decrypt(
                            &self.key,
                            &nonce,
                            &aad,
                            ciphertext_buffer.as_ref(),
                            &tag,
                            &mut writer
                        );
                        let cleartext_buffer = writer.into_inner();

                        if res.is_ok() {
                            mem::replace(&mut self.state, V1State::ReadingNextBlock {
                               aad: tag,
                            });
                            return (self, buf, Ok(Some(cleartext_buffer.freeze())))
                        } else {
                            mem::replace(&mut self.state, V1State::Errored);
                            return (self, buf, Err(V1Error::TagMismatch));
                        }
                    }
                }
            }
        }
    }
}

