extern crate tokio_aead;
extern crate futures;
extern crate bytes;
extern crate stderrlog;

use std::cmp::min;

use futures::stream::Stream;
use futures::stream;
use futures::future;
use bytes::{Bytes, BytesMut};

use tokio_aead::AEAD;

mod common;

fn producer(blocksize: usize, length: usize) -> Box<Stream<Item=Bytes, Error=()>> {
    let stream = stream::unfold((blocksize, length), |(blocksize, length)| {
        if length == 0 {
            return None
        }

        let to_write = min(blocksize, length);

        let mut buf = BytesMut::with_capacity(to_write);
        buf.resize(to_write, 0);

        Some(future::ok((buf.freeze(), (blocksize, length - to_write))))
    });

    Box::new(stream)
}

static KEY: [u8; 32] = [
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
];

#[test]
fn test_encryption() {
    common::setup();

    let input = producer(8192, 10*8192 + 3);
    let aead = AEAD::new(&KEY, 4096);

    let mut output = aead.decrypt(aead.encrypt(input)).wait();

    for _ in 0..20 {
        let mut left = BytesMut::with_capacity(4096);
        left.resize(4096, 0);
        let left = left.freeze();
        assert_eq!(Some(Ok(left)), output.next());
    }

    let mut left = BytesMut::with_capacity(3);
    left.resize(3, 0);
    let left = left.freeze();

    assert_eq!(Some(Ok(left)), output.next());
    assert_eq!(None, output.next());
}


