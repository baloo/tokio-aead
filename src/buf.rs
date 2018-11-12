use std::collections::VecDeque;
use std::cmp::min;

use bytes::{ByteOrder, BigEndian};

pub struct List<Payload> {
    bufs: VecDeque<Payload>,
    current_len: usize,
    current_pos: usize,
}

impl<Payload> List<Payload> {
    pub fn new() -> Self {
        Self {
            bufs: VecDeque::with_capacity(2),
            current_len: 0,
            current_pos: 0,
        }
    }

    //pub fn len(&self) -> usize {
    //    self.current_len
    //}

    pub fn remaining(&self) -> usize {
        self.current_len - self.current_pos
    }

    pub fn reader(self) -> Reader<Payload> {
        Reader {
            inner: self
        }
    }
}

impl<Payload> List<Payload>
    where Payload: AsRef<[u8]> {
    pub fn push(&mut self, data: Payload) {
        self.current_len += data.as_ref().len();
        self.bufs.push_back(data);
    }

    fn pop_front(&mut self) {
        if let Some(el) = self.bufs.pop_front() {
            self.current_len -= el.as_ref().len();
            self.current_pos = 0;
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    NoEnoughBytes,
}

pub struct Reader<Payload> {
    inner: List<Payload>
}

impl<Payload> Reader<Payload> {
    pub fn remaining(&self) -> usize {
        self.inner.remaining()
    }

    pub fn get_inner(self) -> List<Payload> {
        self.inner
    }
}

impl<Payload> Reader<Payload>
    where Payload: AsRef<[u8]> {
    pub fn read(&mut self, dst: &mut [u8]) -> Result<(), Error> {
        if self.inner.remaining() < dst.len() {
            return Err(Error::NoEnoughBytes)
        }
        let mut remaining = dst.len();
        let mut pos = 0;

        while remaining > 0 {
            let remaining_len_after_copy = {
                let cur_element = self.inner.bufs.front().unwrap().as_ref();
                let remaining_len_first = cur_element.len() - self.inner.current_pos;
                let to_copy = min(remaining, remaining_len_first);

                dst[pos..pos+to_copy].copy_from_slice(&cur_element[self.inner.current_pos..self.inner.current_pos+to_copy]);

                pos += to_copy;
                remaining -= to_copy;
                self.inner.current_pos += to_copy;

                cur_element.len() - self.inner.current_pos
            };
            if remaining_len_after_copy == 0 {
                self.inner.pop_front()
            }
        }

        Ok(())
    }

    pub fn read_u32_be(&mut self) -> Result<u32, Error> {
        let mut buf = [0_u8; 4];
        self.read(&mut buf)?;
        Ok(BigEndian::read_u32(&buf))
    }
}

#[cfg(test)]
mod tests {
    use super::{List, Error};
    use bytes::Bytes;

    #[test]
    fn test_append() {
         let mut buf = List::new();
         buf.push(Bytes::from(&b"h"[..]));
         buf.push(Bytes::from(&b"ell"[..]));
         buf.push(Bytes::from(&b"o, world"[..]));

         assert_eq!(buf.remaining(), 12);
    }

    #[test]
    fn test_read() {
         let mut buf = List::new();
         buf.push(Bytes::from(&b"hello"[..]));
         buf.push(Bytes::from(&b", world"[..]));

         let mut buf = buf.reader();

         let mut out = [0u8; 4];
         assert_eq!(Ok(()), buf.read(&mut out));
         assert_eq!(&out, b"hell");
         assert_eq!(Ok(()), buf.read(&mut out));
         assert_eq!(&out, b"o, w");

         let buf = buf.get_inner();
         assert_eq!(buf.remaining(), 4);
    }

    #[test]
    fn test_need_more_bytes() {
         let mut buf = List::new();
         buf.push(Bytes::from(&b"hello"[..]));
         let mut out = [0u8; 6];

         let mut buf = buf.reader();
         assert_eq!(Err(Error::NoEnoughBytes), buf.read(&mut out));
         assert_eq!(&out, &[0u8; 6]);

         let mut buf = buf.get_inner();
         buf.push(Bytes::from(&b", world"[..]));
         let mut buf = buf.reader();


         assert_eq!(Ok(()), buf.read(&mut out));
         assert_eq!(&out, b"hello,");
         let mut out = [0u8; 1];
         assert_eq!(Ok(()), buf.read(&mut out));
         assert_eq!(&out, b" ");
    }
}
