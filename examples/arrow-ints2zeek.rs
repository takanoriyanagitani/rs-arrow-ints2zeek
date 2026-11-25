use std::io;
use std::process::ExitCode;

use io::BufWriter;
use io::Write;

use rs_arrow_ints2zeek::CompressionLevel;
use rs_arrow_ints2zeek::SeekTable;

use arrow_array::RecordBatch;
use arrow_array::record_batch;

fn example_records() -> impl Iterator<Item = Result<RecordBatch, io::Error>> {
    vec![
        record_batch!(
            ("key", Int32, (48..80).collect::<Vec<_>>()),
            ("val", Int32, (48..80).collect::<Vec<_>>())
        )
        .map_err(io::Error::other),
        record_batch!(
            ("key", Int32, (80..112).collect::<Vec<_>>()),
            ("val", Int32, (80..112).collect::<Vec<_>>())
        )
        .map_err(io::Error::other),
    ]
    .into_iter()
}

fn sub() -> Result<(), io::Error> {
    let o = io::stdout();
    let mut ol = o.lock();
    {
        let mut bw = BufWriter::new(&mut ol);
        let mut tabs: Vec<SeekTable> = vec![];
        let level: CompressionLevel = CompressionLevel::BEST1;
        let recs = example_records();
        level.recs2zeek2wtr(recs, &mut bw, 0, &mut tabs)?;
    }
    ol.flush()
}

fn main() -> ExitCode {
    sub().map(|_| ExitCode::SUCCESS).unwrap_or_else(|e| {
        eprintln!("{e}");
        ExitCode::FAILURE
    })
}
