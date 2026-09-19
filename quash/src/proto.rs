use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const KIND_DATA: u8 = 0;
pub const KIND_ACK: u8 = 1;
pub const KIND_HELLO: u8 = 2;
pub const KIND_WELCOME: u8 = 3;
pub const KIND_REJECT: u8 = 4;
pub const KIND_FIN: u8 = 5;

pub const SESSION_ID_LEN: usize = 16;

/// A frame on the session stream. Bulk SSH bytes travel as `Data` frames
/// tagged with their absolute offset in the stream, so that after a reconnect
/// the sender can resume from the offset the receiver reports and the receiver
/// can discard any replayed bytes.
#[derive(Debug)]
pub enum Frame {
    Data {
        offset: u64,
        payload: Bytes,
    },
    Ack {
        offset: u64,
    },
    Hello {
        session_id: [u8; SESSION_ID_LEN],
        applied: u64,
        resume: bool,
    },
    Welcome {
        applied: u64,
    },
    Reject,
    Fin,
}

pub async fn read_frame<R>(reader: &mut R) -> std::io::Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    let mut kind = [0u8; 1];
    if reader.read(&mut kind).await? == 0 {
        return Ok(None);
    }
    match kind[0] {
        KIND_DATA => {
            let offset = read_u64(reader).await?;
            let len = read_u32(reader).await? as usize;
            let mut payload = vec![0u8; len];
            reader.read_exact(&mut payload).await?;
            Ok(Some(Frame::Data {
                offset,
                payload: payload.into(),
            }))
        }
        KIND_ACK => Ok(Some(Frame::Ack {
            offset: read_u64(reader).await?,
        })),
        KIND_HELLO => {
            let mut session_id = [0u8; SESSION_ID_LEN];
            reader.read_exact(&mut session_id).await?;
            let applied = read_u64(reader).await?;
            let resume = reader.read_u8().await? != 0;
            Ok(Some(Frame::Hello {
                session_id,
                applied,
                resume,
            }))
        }
        KIND_WELCOME => Ok(Some(Frame::Welcome {
            applied: read_u64(reader).await?,
        })),
        KIND_REJECT => Ok(Some(Frame::Reject)),
        KIND_FIN => Ok(Some(Frame::Fin)),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown frame kind {other}"),
        )),
    }
}

pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match frame {
        Frame::Data { offset, payload } => {
            let len = u32::try_from(payload.len()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large")
            })?;
            let mut header = [0u8; 13];
            header[0] = KIND_DATA;
            header[1..9].copy_from_slice(&offset.to_be_bytes());
            header[9..13].copy_from_slice(&len.to_be_bytes());
            writer.write_all(&header).await?;
            writer.write_all(payload).await?;
        }
        Frame::Ack { offset } => {
            let mut header = [0u8; 9];
            header[0] = KIND_ACK;
            header[1..9].copy_from_slice(&offset.to_be_bytes());
            writer.write_all(&header).await?;
        }
        Frame::Hello {
            session_id,
            applied,
            resume,
        } => {
            let mut header = [0u8; 1 + SESSION_ID_LEN + 8 + 1];
            header[0] = KIND_HELLO;
            header[1..=SESSION_ID_LEN].copy_from_slice(session_id);
            header[1 + SESSION_ID_LEN..1 + SESSION_ID_LEN + 8]
                .copy_from_slice(&applied.to_be_bytes());
            header[1 + SESSION_ID_LEN + 8] = u8::from(*resume);
            writer.write_all(&header).await?;
        }
        Frame::Welcome { applied } => {
            let mut header = [0u8; 9];
            header[0] = KIND_WELCOME;
            header[1..9].copy_from_slice(&applied.to_be_bytes());
            writer.write_all(&header).await?;
        }
        Frame::Reject => {
            writer.write_all(&[KIND_REJECT]).await?;
        }
        Frame::Fin => {
            writer.write_all(&[KIND_FIN]).await?;
        }
    }
    writer.flush().await
}

async fn read_u64<R>(reader: &mut R) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf).await?;
    Ok(u64::from_be_bytes(buf))
}

async fn read_u32<R>(reader: &mut R) -> std::io::Result<u32>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf).await?;
    Ok(u32::from_be_bytes(buf))
}
