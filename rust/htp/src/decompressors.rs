use brotli;
use nom::Parser as _;
use std::{
    io::{Cursor, Write},
    time::Instant,
};

/// Buffer compression output to this chunk size.
const ENCODING_CHUNK_SIZE: usize = 8192;

/// Default LZMA dictionary memory limit in bytes.
const DEFAULT_LZMA_MEMLIMIT: usize = 1_048_576;
/// Default number of LZMA layers to pass to the decompressor.
const DEFAULT_LZMA_LAYERS: u32 = 1;
/// Default max output size for a compression bomb in bytes (1 MB default).
const DEFAULT_BOMB_LIMIT: u64 = 1_048_576;
/// Default compressed-to-decrompressed ratio that should not be exceeded during decompression.
const DEFAULT_BOMB_RATIO: u64 = 2048;
/// Default time limit for a decompression bomb in microseconds.
const DEFAULT_TIME_LIMIT: u32 = 100_000;
/// Default number of iterations before checking the time limit.
const DEFAULT_TIME_FREQ_TEST: u32 = 256;
/// Default number of layers that will be decompressed
const DEFAULT_LAYER_LIMIT: u32 = 2;

#[derive(Copy, Clone)]
/// Decompression options
pub(crate) struct Options {
    /// lzma options or None to disable lzma.
    lzma: Option<lzma_rs::decompress::Options>,
    /// Max number of LZMA layers to pass to the decompressor.
    lzma_layers: Option<u32>,
    /// max output size for a compression bomb.
    bomb_limit: u64,
    /// max compressed-to-decrompressed ratio that should not be exceeded during decompression.
    bomb_ratio: u64,
    /// max time for a decompression bomb in microseconds.
    time_limit: u32,
    /// number of iterations to before checking the time_limit.
    time_test_freq: u32,
    /// Max number of layers of compression we will decompress
    layer_limit: Option<u32>,
}

impl Options {
    /// Set the lzma memlimit.
    ///
    /// A value of 0 will disable lzma.
    pub(crate) fn set_lzma_memlimit(&mut self, memlimit: usize) {
        self.lzma = if memlimit == 0 {
            None
        } else {
            Some(lzma_rs::decompress::Options {
                memlimit: Some(memlimit),
                ..Default::default()
            })
        }
    }

    /// Configures the maximum layers passed to lzma-rs.
    pub(crate) fn set_lzma_layers(&mut self, layers: Option<u32>) {
        self.lzma_layers = layers;
    }

    /// Gets the maximum layers passed to lzma-rs.
    pub(crate) fn get_lzma_layers(&self) -> Option<u32> {
        self.lzma_layers
    }

    /// Get the compression bomb limit.
    pub(crate) fn get_bomb_limit(&self) -> u64 {
        self.bomb_limit
    }

    /// Set the compression bomb limit.
    pub(crate) fn set_bomb_limit(&mut self, bomblimit: u64) {
        self.bomb_limit = bomblimit;
    }

    /// Get the bomb ratio.
    pub(crate) fn get_bomb_ratio(&self) -> u64 {
        self.bomb_ratio
    }

    /// Set the bomb ratio.
    #[cfg(test)]
    pub(crate) fn set_bomb_ratio(&mut self, bomb_ratio: u64) {
        self.bomb_ratio = bomb_ratio;
    }

    /// Get the compression time limit in microseconds.
    pub(crate) fn get_time_limit(&self) -> u32 {
        self.time_limit
    }

    /// Set the compression time limit in microseconds.
    pub(crate) fn set_time_limit(&mut self, time_limit: u32) {
        self.time_limit = time_limit
    }

    /// Get the time test frequency.
    pub(crate) fn get_time_test_freq(&self) -> u32 {
        self.time_test_freq
    }

    /// Get the decompression layer limit.
    pub(crate) fn get_layer_limit(&self) -> Option<u32> {
        self.layer_limit
    }

    /// Set the decompression layer limit.
    pub(crate) fn set_layer_limit(&mut self, layer_limit: Option<u32>) {
        self.layer_limit = layer_limit;
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            lzma: Some(lzma_rs::decompress::Options {
                memlimit: Some(DEFAULT_LZMA_MEMLIMIT),
                ..Default::default()
            }),
            lzma_layers: Some(DEFAULT_LZMA_LAYERS),
            bomb_limit: DEFAULT_BOMB_LIMIT,
            bomb_ratio: DEFAULT_BOMB_RATIO,
            time_limit: DEFAULT_TIME_LIMIT,
            time_test_freq: DEFAULT_TIME_FREQ_TEST,
            layer_limit: Some(DEFAULT_LAYER_LIMIT),
        }
    }
}

/// Describes a decompressor that is able to restart and passthrough data.
/// Actual decompression is done using the `Write` trait.
pub(crate) trait Decompress: Write {
    /// Restarts the decompressor to try the same one again or a different one.
    fn restart(&mut self) -> std::io::Result<()>;

    /// Tells all decompressors to passthrough their data instead of
    /// decompressing to directly call the callback
    fn set_passthrough(&mut self, passthrough: bool);

    /// Indicates that we have reached the end of data. This would be equivalent
    /// to sending a NULL pointer in C and may be used by the hooks.
    fn finish(&mut self) -> std::io::Result<()>;
}

/// Type alias for callback function.
pub(crate) type CallbackFn = Box<dyn FnMut(Option<&[u8]>) -> Result<usize, std::io::Error>>;

/// Simple wrapper around a closure to chain it to the other decompressors
pub(crate) struct CallbackWriter(CallbackFn);

impl CallbackWriter {
    /// Create a new CallbackWriter.
    pub(crate) fn new(cbk: CallbackFn) -> Self {
        CallbackWriter(cbk)
    }
}

impl Write for CallbackWriter {
    fn write(&mut self, data: &[u8]) -> std::result::Result<usize, std::io::Error> {
        (self.0)(Some(data))
    }

    fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
        Ok(())
    }
}

impl Decompress for CallbackWriter {
    fn restart(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn set_passthrough(&mut self, _passthrough: bool) {}

    fn finish(&mut self) -> std::io::Result<()> {
        (self.0)(None)?;
        Ok(())
    }
}

/// Type of compression.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum HtpContentEncoding {
    /// No compression.
    None,
    /// Gzip compression.
    Gzip,
    /// Deflate compression (RFC 1951).
    Deflate,
    /// Deflate compression with zlib header (RFC 1950)
    Zlib,
    /// LZMA compression.
    Lzma,
    /// Brotli compression.
    Brotli,
}

//a cursor turning EOF into blocking errors
#[derive(Debug)]
struct BlockingCursor {
    pub cursor: Cursor<Box<[u8]>>,
}

impl BlockingCursor {
    fn new() -> BlockingCursor {
        BlockingCursor {
            cursor: Cursor::new(Box::new([0u8; ENCODING_CHUNK_SIZE])),
        }
    }
    pub fn set_position(&mut self, pos: u64) {
        self.cursor.set_position(pos)
    }
    fn position(&self) -> u64 {
        self.cursor.position()
    }
    pub fn get_ref(&self) -> &[u8] {
        self.cursor.get_ref()
    }
}

// we need to implement this as flate2 and brotli crates
// will read from this object
impl Write for BlockingCursor {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        //use the cursor, except it turns eof into blocking error
        let r = self.cursor.write(buf);
        match r {
            Err(ref err) => {
                if err.kind() == std::io::ErrorKind::UnexpectedEof {
                    return Err(std::io::ErrorKind::WouldBlock.into());
                }
            }
            Ok(0) => {
                //regular EOF turned into blocking error
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            Ok(_n) => {}
        }
        r
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The outer decompressor tracks the number of callbacks and time spent
/// decompressing.
pub(crate) struct Decompressor {
    /// First decompressor to call
    inner: Box<dyn Decompress>,
    /// Time we started decompression
    time_before: Option<Instant>,
    /// Time spent decompressing so far in microseconds (usec)
    time_spent: u64,
    /// Number of times the callback was called
    nb_callbacks: u32,
}

impl Decompressor {
    /// Creates a new decompressor from a struct implementing the Decompress trait.
    fn new(inner: Box<dyn Decompress>) -> Self {
        Self {
            inner,
            time_before: None,
            time_spent: 0,
            nb_callbacks: 0,
        }
    }

    /// Creates a new decompressor from a callback to call when decompressed
    /// data is ready.
    fn callback(callback: CallbackFn) -> Self {
        Self::new(Box::new(CallbackWriter::new(callback)))
    }

    /// Prepends a decompressor to this chain by consuming `self.inner`
    /// and creating a new Decompressor.
    ///
    /// Note that decompressors should be added in the same order the data was
    /// compressed, starting with the callback.
    ///
    pub(crate) fn prepend(
        self, encoding: HtpContentEncoding, options: Options,
    ) -> std::io::Result<Self> {
        match encoding {
            HtpContentEncoding::None => Ok(Decompressor::new(self.inner)),
            HtpContentEncoding::Gzip
            | HtpContentEncoding::Deflate
            | HtpContentEncoding::Zlib
            | HtpContentEncoding::Brotli
            | HtpContentEncoding::Lzma => Ok(Decompressor::new(Box::new(InnerDecompressor::new(
                encoding, self.inner, options,
            )?))),
        }
    }

    /// Creates a new decompressor with `encoding` and adds a callback to be called
    /// when data is ready.
    pub(crate) fn new_with_callback(
        encoding: HtpContentEncoding, callback: CallbackFn, options: Options,
    ) -> std::io::Result<Self> {
        Self::callback(callback).prepend(encoding, options)
    }

    /// Starts the decompression timer.
    fn timer_start(&mut self) {
        self.time_before.replace(Instant::now());
    }

    /// Stops the decompression timer, updates and returns the time spent
    /// decompressing in microseconds (usec).
    pub(crate) fn timer_reset(&mut self) -> Option<u64> {
        let now = Instant::now();
        if let Some(time_before) = self.time_before.replace(now) {
            // it is unlikely that more than 2^64 will be spent on a single stream
            self.time_spent = self
                .time_spent
                .wrapping_add(now.duration_since(time_before).as_micros() as u64);
            Some(self.time_spent)
        } else {
            None
        }
    }

    /// Increments the number of times the callback was called.
    pub(crate) fn callback_inc(&mut self) -> u32 {
        self.nb_callbacks = self.nb_callbacks.wrapping_add(1);
        self.nb_callbacks
    }

    /// Returns the time spent decompressing in microseconds (usec).
    pub(crate) fn time_spent(&self) -> u64 {
        self.time_spent
    }

    /// Decompress the input `data` by calling the chain of decompressors and
    /// the data callback.
    ///
    /// This will reset the number of callbacks called and restart the
    /// decompression timer.
    pub(crate) fn decompress(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.nb_callbacks = 0;
        self.timer_start();

        let result = self.inner.write_all(data).and_then(|_| self.inner.flush());

        self.timer_reset();
        result
    }

    /// Notify decompressors that the end of stream as reached. This is equivalent
    /// to sending a NULL data pointer.
    pub(crate) fn finish(&mut self) -> std::io::Result<()> {
        self.inner.finish()
    }

    /// Set this decompressor to passthrough
    pub(crate) fn set_passthrough(&mut self, passthrough: bool) {
        self.inner.set_passthrough(passthrough)
    }
}

impl std::fmt::Debug for Decompressor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Decompressor")
            .field("time_spent", &self.time_spent)
            .field("nb_callbacks", &self.nb_callbacks)
            .finish()
    }
}

/// Trait that represents the decompression writers (gzip, deflate, etc.) and
/// methods needed to write to a temporary buffer.
trait BufWriter: Write {
    /// Get a mutable reference to the buffer.
    fn get_mut(&mut self) -> Option<&mut BlockingCursor>;
    /// Notify end of data.
    fn finish(self: Box<Self>) -> std::io::Result<BlockingCursor>;
    /// Attempt to finish this output stream, writing out final chunks of data.
    fn try_finish(&mut self) -> std::io::Result<()>;
}

/// A BufWriter that doesn't consume any data.
///
/// This should be used exclusively with passthrough mode.
struct NullBufWriter(BlockingCursor);

impl Write for NullBufWriter {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Ok(0)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl BufWriter for NullBufWriter {
    fn get_mut(&mut self) -> Option<&mut BlockingCursor> {
        Some(&mut self.0)
    }

    fn finish(self: Box<Self>) -> std::io::Result<BlockingCursor> {
        Ok(self.0)
    }

    fn try_finish(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
enum GzState {
    Start,
    Xlen,
    Extra,
    Filename,
    Comment,
    Crc,
    AfterHeader,
}

/// Wrapper around a gzip header parser and a deflate decoder.
/// We parse the header separately because we want to be tolerant of
/// checksum or other gzip errors that do not affect our ability
/// to decompress the data stream but would cause 'correct' gzip decoders
/// to fail. We want to be tolerant of gzip errors because browsers
/// are apparently tolerant of gzip errors
///
/// https://noxxi.de/research/http-evader-explained-5-gzip.html
struct GzipBufWriter {
    buffer: Vec<u8>,
    flags: u8,
    xlen: u16,
    inner: flate2::write::DeflateDecoder<BlockingCursor>,
    state: GzState,
}

impl GzipBufWriter {
    fn new(buf: BlockingCursor) -> Self {
        GzipBufWriter {
            buffer: Vec::with_capacity(10),
            flags: 0,
            xlen: 0,
            inner: flate2::write::DeflateDecoder::new(buf),
            state: GzState::Start,
        }
    }

    fn parse_start(data: &[u8]) -> nom::IResult<&[u8], u8> {
        use nom::bytes::streaming::tag;
        use nom::number::streaming::{le_i32, le_u8};

        let (rest, (_, flags, _mtime, _xfl, _operating_system)) =
            (tag(&b"\x1f\x8b\x08"[..]), le_u8, le_i32, le_u8, le_u8).parse(data)?;
        Ok((rest, flags))
    }
}

impl Write for GzipBufWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        use nom::bytes::streaming::{tag, take_until};
        use nom::number::streaming::le_u16;

        const FHCRC: u8 = 1 << 1;
        const FEXTRA: u8 = 1 << 2;
        const FNAME: u8 = 1 << 3;
        const FCOMMENT: u8 = 1 << 4;

        let (mut parse, direct) = if !self.buffer.is_empty() && self.state == GzState::Start {
            self.buffer.extend_from_slice(data);
            (self.buffer.as_ref(), false)
        } else {
            (data, true)
        };

        loop {
            match self.state {
                GzState::Start => match GzipBufWriter::parse_start(parse) {
                    Ok((rest, flags)) => {
                        parse = rest;
                        self.flags = flags;
                        self.state = GzState::Xlen;
                    }
                    Err(nom::Err::Incomplete(_)) => {
                        if direct {
                            self.buffer.extend_from_slice(data);
                        }
                        return Ok(data.len());
                    }
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Could not parse gzip header",
                        ));
                    }
                },
                GzState::Xlen => {
                    if self.flags & FEXTRA != 0 {
                        match le_u16::<&[u8], nom::error::Error<&[u8]>>(parse) {
                            Ok((rest, xlen)) => {
                                parse = rest;
                                self.xlen = xlen;
                            }
                            Err(nom::Err::Incomplete(_)) => {
                                return Ok(data.len() - parse.len());
                            }
                            Err(_) => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    "Could not parse gzip header",
                                )); // this one is unreachable
                            }
                        }
                    }
                    self.state = GzState::Extra;
                }
                GzState::Extra => {
                    if self.xlen > 0 {
                        if parse.len() < self.xlen as usize {
                            self.xlen -= parse.len() as u16;
                            return Ok(data.len());
                        }
                        parse = &parse[self.xlen as usize..];
                    }
                    self.state = GzState::Filename;
                }
                GzState::Filename => {
                    if self.flags & FNAME != 0 {
                        match (
                            take_until::<&[u8], &[u8], nom::error::Error<&[u8]>>(b"\0" as &[u8]),
                            tag(&b"\0"[..]),
                        )
                            .parse(parse)
                        {
                            Ok((rest, _)) => {
                                parse = rest;
                            }
                            Err(nom::Err::Incomplete(_)) => {
                                return Ok(data.len());
                            }
                            Err(_) => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    "Could not parse gzip header",
                                )); // this one is unreachable
                            }
                        }
                    }
                    self.state = GzState::Comment;
                }
                GzState::Comment => {
                    if self.flags & FCOMMENT != 0 {
                        match (
                            take_until::<&[u8], &[u8], nom::error::Error<&[u8]>>(b"\0" as &[u8]),
                            tag(&b"\0"[..]),
                        )
                            .parse(parse)
                        {
                            Ok((rest, _)) => {
                                parse = rest;
                            }
                            Err(nom::Err::Incomplete(_)) => {
                                return Ok(data.len());
                            }
                            Err(_) => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    "Could not parse gzip header",
                                )); // this one is unreachable
                            }
                        }
                    }
                    self.state = GzState::Crc;
                }
                GzState::Crc => {
                    if self.flags & FHCRC != 0 {
                        match le_u16::<&[u8], nom::error::Error<&[u8]>>(parse) {
                            Ok((rest, _)) => {
                                parse = rest;
                            }
                            Err(nom::Err::Incomplete(_)) => {
                                return Ok(data.len() - parse.len());
                            }
                            Err(_) => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    "Could not parse gzip header",
                                )); // this one is unreachable
                            }
                        }
                    }
                    self.state = GzState::AfterHeader;
                    return Ok(data.len() - parse.len());
                }
                GzState::AfterHeader => {
                    return self.inner.write(parse);
                }
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl BufWriter for GzipBufWriter {
    fn get_mut(&mut self) -> Option<&mut BlockingCursor> {
        Some(self.inner.get_mut())
    }

    fn finish(self: Box<Self>) -> std::io::Result<BlockingCursor> {
        self.inner.finish()
    }

    fn try_finish(&mut self) -> std::io::Result<()> {
        self.inner.try_finish()
    }
}

/// Simple wrapper around a deflate implementation
struct DeflateBufWriter(flate2::write::DeflateDecoder<BlockingCursor>);

impl Write for DeflateBufWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.write(data)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl BufWriter for DeflateBufWriter {
    fn get_mut(&mut self) -> Option<&mut BlockingCursor> {
        Some(self.0.get_mut())
    }

    fn finish(self: Box<Self>) -> std::io::Result<BlockingCursor> {
        self.0.finish()
    }

    fn try_finish(&mut self) -> std::io::Result<()> {
        self.0.try_finish()
    }
}

/// Simple wrapper around a zlib implementation
struct ZlibBufWriter(flate2::write::ZlibDecoder<BlockingCursor>);

impl Write for ZlibBufWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.write(data)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl BufWriter for ZlibBufWriter {
    fn get_mut(&mut self) -> Option<&mut BlockingCursor> {
        Some(self.0.get_mut())
    }

    fn finish(self: Box<Self>) -> std::io::Result<BlockingCursor> {
        self.0.finish()
    }

    fn try_finish(&mut self) -> std::io::Result<()> {
        self.0.try_finish()
    }
}

/// Simple wrapper around an lzma implementation
struct LzmaBufWriter(lzma_rs::decompress::Stream<BlockingCursor>);

impl Write for LzmaBufWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.write(data)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl BufWriter for LzmaBufWriter {
    fn get_mut(&mut self) -> Option<&mut BlockingCursor> {
        self.0.get_output_mut()
    }

    fn finish(self: Box<Self>) -> std::io::Result<BlockingCursor> {
        self.0.finish().map_err(|e| match e {
            lzma_rs::error::Error::IoError(e) => e,
            lzma_rs::error::Error::HeaderTooShort(e) => std::io::Error::other(format!("{e}")),
            lzma_rs::error::Error::LzmaError(e) | lzma_rs::error::Error::XzError(e) => {
                std::io::Error::other(e)
            }
        })
    }

    fn try_finish(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Simple wrapper around an lzma implementation
struct BrotliBufWriter(brotli::DecompressorWriter<BlockingCursor>);

impl Write for BrotliBufWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.write(data)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl BufWriter for BrotliBufWriter {
    fn get_mut(&mut self) -> Option<&mut BlockingCursor> {
        Some(self.0.get_mut())
    }

    fn finish(self: Box<Self>) -> std::io::Result<BlockingCursor> {
        self.0
            .into_inner()
            .map_err(|_e| std::io::Error::other("brotli"))
    }

    fn try_finish(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Structure that represents each decompressor in the chain.
struct InnerDecompressor {
    /// Decoder implementation that will write to a temporary buffer.
    writer: Option<Box<dyn BufWriter>>,
    /// Next decompressor to call.
    inner: Option<Box<dyn Decompress>>,
    /// Encoding type of the decompressor.
    encoding: HtpContentEncoding,
    /// Indicates whether to pass through the data without calling the writer.
    passthrough: bool,
    /// Tracks the number of restarts
    restarts: u8,
    /// Options for decompression
    options: Options,
}

impl InnerDecompressor {
    /// Returns a new writer according to the content encoding type and whether to passthrough.
    fn writer(
        encoding: HtpContentEncoding, options: &Options,
    ) -> std::io::Result<(Box<dyn BufWriter>, bool)> {
        let buf = BlockingCursor::new();

        match encoding {
            HtpContentEncoding::Gzip => Ok((Box::new(GzipBufWriter::new(buf)), false)),
            HtpContentEncoding::Deflate => Ok((
                Box::new(DeflateBufWriter(flate2::write::DeflateDecoder::new(buf))),
                false,
            )),
            HtpContentEncoding::Zlib => Ok((
                Box::new(ZlibBufWriter(flate2::write::ZlibDecoder::new(buf))),
                false,
            )),
            HtpContentEncoding::Brotli => Ok((
                Box::new(BrotliBufWriter(brotli::DecompressorWriter::new(
                    buf,
                    ENCODING_CHUNK_SIZE,
                ))),
                false,
            )),
            HtpContentEncoding::Lzma => {
                if let Some(options) = options.lzma {
                    Ok((
                        Box::new(LzmaBufWriter(
                            lzma_rs::decompress::Stream::new_with_options(&options, buf),
                        )),
                        false,
                    ))
                } else {
                    Ok((Box::new(NullBufWriter(buf)), true))
                }
            }
            HtpContentEncoding::None => Err(std::io::Error::other("expected a valid encoding")),
        }
    }

    /// Create a new `InnerDecompressor` given a content encoding type and the
    /// next (`inner`) decompressor to call.
    fn new(
        encoding: HtpContentEncoding, inner: Box<dyn Decompress>, options: Options,
    ) -> std::io::Result<Self> {
        let (writer, passthrough) = Self::writer(encoding, &options)?;
        Ok(Self {
            inner: Some(inner),
            encoding,
            writer: Some(writer),
            passthrough,
            restarts: 0,
            options,
        })
    }

    /// Tries to pass data to the callback instead of calling the writers.
    ///
    /// This will set passthrough mode on success or revert on error.
    fn try_passthrough(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.set_passthrough(true);
        if let Some(inner) = &mut self.inner {
            let result = inner.write(data);
            if result.is_err() {
                self.set_passthrough(false);
            }
            result
        } else {
            Ok(data.len())
        }
    }

    /// Flushes the writer and the temporary buffer it writes to.
    ///
    /// The writer should be taken out of its slot and passed directly instead of
    /// `self.writer` to avoid holding multiple mutable references.
    fn flush_writer(&mut self, writer: &mut Box<dyn BufWriter>) -> std::io::Result<()> {
        if let Some(mut inner) = self.inner.take() {
            loop {
                let result = writer.flush();

                // Flush all of the bytes the writer has written to our temporary
                // buffer of fixed size.
                if let Some(cursor) = writer.get_mut() {
                    inner.write_all(&cursor.get_ref()[0..cursor.position() as usize])?;
                    cursor.set_position(0);
                }

                // Continue flushing if the flush resulted in a `WriteZero`. This
                // error indicates that the writer was unable to write all bytes
                // to our temporary buffer, likely because it was full.
                if let Err(e) = result {
                    match e.kind() {
                        std::io::ErrorKind::WriteZero => {}
                        _ => {
                            self.restart()?;
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
            self.inner.replace(inner);
            Ok(())
        } else {
            Err(std::io::Error::other("nothing to flush to"))
        }
    }

    fn try_finish(&mut self, writer: &mut Box<dyn BufWriter>) -> bool {
        loop {
            let redo = match writer.try_finish() {
                Err(e) => e.kind() == std::io::ErrorKind::WriteZero,
                _ => false,
            };
            if let Some(cursor) = writer.get_mut() {
                if cursor.position() > 0 {
                    if let Some(mut inner) = self.inner.take() {
                        _ = inner.write_all(&cursor.get_ref()[0..cursor.position() as usize]);
                        cursor.set_position(0);
                        self.inner.replace(inner);
                        if redo {
                            continue;
                        }
                        return true;
                    }
                }
            }
            return false;
        }
    }
}

impl Write for InnerDecompressor {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        // Passthrough mode
        if self.passthrough {
            if let Some(inner) = &mut self.inner {
                inner.write(data)
            } else {
                Ok(data.len())
            }

        // Take the writer out of its slot to avoid holding multiple mutable
        // references. Any calls using `self.writer` should be avoided while the
        // writer is in this state.
        } else if let Some(mut writer) = self.writer.take() {
            match writer.write(data) {
                Ok(consumed) => {
                    let result = if consumed == 0 {
                        // This could indicate that we have reached the end
                        // of the stream. Any data after the first end of
                        // stream (such as in multipart gzip) is ignored and
                        // we pretend to have consumed this data.
                        Ok(data.len())
                    } else {
                        Ok(consumed)
                    };
                    self.writer.replace(writer);
                    result
                }
                Err(e) => {
                    match e.kind() {
                        std::io::ErrorKind::WriteZero => {
                            self.flush_writer(&mut writer)?;
                            // Recursion: the buffer was flushed until `WriteZero`
                            // stopped occuring.
                            self.writer.replace(writer);
                            self.write(data)
                        }
                        _ => {
                            if self.restarts == 0 {
                                let written = self.try_finish(&mut writer);
                                if written {
                                    // error, but some data has been written, stop here
                                    return Err(e);
                                }
                            }
                            // try to restart, any data in the temp buffer will be
                            // discarded
                            if self.restart().is_err() {
                                self.try_passthrough(data)
                            } else {
                                // Recursion: restart will fail after a small
                                // number of attempts
                                self.write(data)
                            }
                        }
                    }
                }
            }
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "writer was not initialized",
            ))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(mut writer) = self.writer.take() {
            self.flush_writer(&mut writer)?;
            self.writer.replace(writer);
        }
        if let Some(inner) = &mut self.inner {
            inner.flush()
        } else {
            Ok(())
        }
    }
}

impl Decompress for InnerDecompressor {
    fn restart(&mut self) -> std::io::Result<()> {
        if self.restarts < 3 {
            // first retry the same encoding type
            self.encoding = match self.encoding {
                HtpContentEncoding::Gzip => HtpContentEncoding::Deflate,
                HtpContentEncoding::Deflate => HtpContentEncoding::Zlib,
                HtpContentEncoding::Zlib => HtpContentEncoding::Gzip,
                // For other encodings, we retry with deflate, zlib and gzip
                HtpContentEncoding::Lzma => HtpContentEncoding::Deflate,
                HtpContentEncoding::Brotli => HtpContentEncoding::Deflate,
                HtpContentEncoding::None => {
                    return Err(std::io::Error::other("expected a valid encoding"))
                }
            };
            let (writer, passthrough) = Self::writer(self.encoding, &self.options)?;
            self.writer = Some(writer);
            if passthrough {
                self.passthrough = passthrough;
            }
            self.restarts += 1;
            Ok(())
        } else {
            Err(std::io::Error::other("too many restart attempts"))
        }
    }

    // Tell all the decompressors to pass through the data instead of calling
    // the writer.
    fn set_passthrough(&mut self, passthrough: bool) {
        self.passthrough = passthrough;
        if let Some(inner) = &mut self.inner {
            inner.set_passthrough(passthrough);
        }
    }

    // Tell all decompressors that there is no more data to receive.
    fn finish(&mut self) -> std::io::Result<()> {
        let output = if let Some(mut writer) = self.writer.take() {
            self.flush_writer(&mut writer)?;
            Some(writer.finish()?)
        } else {
            None
        };

        if let Some(mut inner) = self.inner.take() {
            if let Some(output) = output {
                inner.write_all(&output.get_ref()[..output.position() as usize])?;
            }
            inner.finish()
        } else {
            Ok(())
        }
    }
}

#[test]
fn test_gz_header() {
    // No flags or other bits
    let input = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x00";
    let buf = BlockingCursor::new();
    let mut gzw = GzipBufWriter::new(buf);
    assert_eq!(gzw.write(input).unwrap(), input.len());
    assert_eq!(gzw.state, GzState::AfterHeader);

    // Just CRC
    let input = b"\x1f\x8b\x08\x02\x00\x00\x00\x00\x00\x00\x11\x22";
    let buf = BlockingCursor::new();
    let mut gzw = GzipBufWriter::new(buf);
    assert_eq!(gzw.write(input).unwrap(), input.len());
    assert_eq!(gzw.state, GzState::AfterHeader);

    // Just extra
    let input = b"\x1f\x8b\x08\x04\x00\x00\x00\x00\x00\x00\x04\x00abcd";
    let buf = BlockingCursor::new();
    let mut gzw = GzipBufWriter::new(buf);
    assert_eq!(gzw.write(input).unwrap(), input.len());
    assert_eq!(gzw.state, GzState::AfterHeader);

    // Just filename
    let input = b"\x1f\x8b\x08\x08\x00\x00\x00\x00\x00\x00variable\x00";
    let buf = BlockingCursor::new();
    let mut gzw = GzipBufWriter::new(buf);
    assert_eq!(gzw.write(input).unwrap(), input.len());
    assert_eq!(gzw.state, GzState::AfterHeader);

    // Just comment
    let input = b"\x1f\x8b\x08\x10\x00\x00\x00\x00\x00\x00also variable\x00";
    let buf = BlockingCursor::new();
    let mut gzw = GzipBufWriter::new(buf);
    assert_eq!(gzw.write(input).unwrap(), input.len());
    assert_eq!(gzw.state, GzState::AfterHeader);

    // Extra and Filename
    let input = b"\x1f\x8b\x08\x0c\x00\x00\x00\x00\x00\x00\x05\x00extrafilename\x00";
    let buf = BlockingCursor::new();
    let mut gzw = GzipBufWriter::new(buf);
    assert_eq!(gzw.write(input).unwrap(), input.len());
    assert_eq!(gzw.state, GzState::AfterHeader);

    // Extra and Comment and CRC
    let input = b"\x1f\x8b\x08\x16\x00\x00\x00\x00\x00\x00\x05\x00extracomment\x00\x34\x12";
    let buf = BlockingCursor::new();
    let mut gzw = GzipBufWriter::new(buf);
    assert_eq!(gzw.write(input).unwrap(), input.len());
    assert_eq!(gzw.state, GzState::AfterHeader);

    // Filename and Comment
    let input = b"\x1f\x8b\x08\x18\x00\x00\x00\x00\x00\x00filename\x00comment\x00";
    let buf = BlockingCursor::new();
    let mut gzw = GzipBufWriter::new(buf);
    assert_eq!(gzw.write(input).unwrap(), input.len());
    assert_eq!(gzw.state, GzState::AfterHeader);

    // Extra Filename and Comment and CRC
    let input =
        b"\x1f\x8b\x08\x1e\x00\x00\x00\x00\x00\x00\x05\x00extrafilename\x00comment\x00\x34\x12";
    let buf = BlockingCursor::new();
    let mut gzw = GzipBufWriter::new(buf);
    assert_eq!(gzw.write(input).unwrap(), input.len());
    assert_eq!(gzw.state, GzState::AfterHeader);

    // Too short
    let input = b"\x1f\x8b\x08\x1e\x00\x00\x00\x00\x00\x00\x05\x00extrafilename\x00comment\x00\x34";
    let buf = BlockingCursor::new();
    let mut gzw = GzipBufWriter::new(buf);
    assert_eq!(gzw.write(input).unwrap(), input.len() - 1);
    assert_eq!(gzw.state, GzState::Crc);
    // final missing CRC in header
    let input = b"\x34\xee";
    assert_eq!(gzw.write(input).unwrap(), input.len());
    assert_eq!(gzw.state, GzState::AfterHeader);
    let input = b"\x1f\x8b\x08\x01\x00\x00\x00\x00\x00";
    let buf = BlockingCursor::new();
    let mut gzw = GzipBufWriter::new(buf);
    assert_eq!(gzw.write(input).unwrap(), input.len());
    assert_eq!(gzw.state, GzState::Start);
}
