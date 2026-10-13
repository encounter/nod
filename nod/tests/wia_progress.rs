//! Callback checkpoints for output groups that do not write any bytes.

use std::{io, sync::Arc};

use nod::{
    common::{Compression, Format},
    disc::GCN_MAGIC,
    read::{DiscOptions, DiscReader},
    write::{DiscWriter, FormatOptions, ProcessOptions},
};

const CHUNK: u32 = 0x200000;
const GROUPS: usize = 4;

fn writer(format: Format, repeated: bool) -> DiscWriter {
    let mut data = vec![0u8; CHUNK as usize * GROUPS];
    data[..6].copy_from_slice(b"GZZE01");
    data[0x1c..0x20].copy_from_slice(&GCN_MAGIC);
    if repeated {
        data[CHUNK as usize..].fill(0x5a);
    }
    let reader = DiscReader::new_stream(Box::new(Arc::<[u8]>::from(data)), &DiscOptions {
        #[cfg(feature = "threading")]
        preloader_threads: 0,
        ..Default::default()
    })
    .unwrap();
    DiscWriter::new(reader, &FormatOptions {
        format,
        compression: Compression::None,
        block_size: CHUNK,
    })
    .unwrap()
}

fn options() -> ProcessOptions {
    ProcessOptions {
        #[cfg(feature = "threading")]
        processor_threads: 0,
        ..Default::default()
    }
}

#[test]
fn empty_and_reused_groups_have_progress_checkpoints() {
    for format in [Format::Wia, Format::Rvz] {
        for repeated in [false, true] {
            let mut checkpoints = Vec::new();
            writer(format, repeated)
                .process(
                    |data, position, total| {
                        if data.is_empty() {
                            checkpoints.push((position, total));
                        }
                        Ok(())
                    },
                    &options(),
                )
                .unwrap();
            assert_eq!(checkpoints.len(), GROUPS + 2, "{format:?}, repeated={repeated}");
            assert!(checkpoints.windows(2).all(|pair| pair[0].0 <= pair[1].0));
            let &(position, total) = checkpoints.last().unwrap();
            assert_eq!(position, total);
        }
    }
}

#[test]
fn callback_errors_stop_at_group_and_finalization_checkpoints() {
    for format in [Format::Wia, Format::Rvz] {
        // Group 3 is empty or reuses the already written second group. The last
        // two callbacks are the pre-digest and post-raw-table checkpoints.
        for repeated in [false, true] {
            for cancel_at in [3, GROUPS + 1, GROUPS + 2] {
                let mut checkpoints = 0;
                let result = writer(format, repeated).process(
                    |data, _, _| {
                        if data.is_empty() {
                            checkpoints += 1;
                            if checkpoints == cancel_at {
                                return Err(io::Error::new(
                                    io::ErrorKind::Interrupted,
                                    "cancelled",
                                ));
                            }
                        }
                        Ok(())
                    },
                    &options(),
                );
                assert!(result.is_err(), "{format:?}, repeated={repeated}, checkpoint={cancel_at}");
                assert_eq!(checkpoints, cancel_at);
            }
        }
    }
}
