use anyhow::{anyhow, Result};
use janus_messages::{
    query_type::TimeInterval, AggregateJob, AggregateJobPutReq, AggregateShareReq,
    AggregateShareResp, CollectReq, CollectResp, HpkeConfig, Report,
};
use prio::codec::Decode;
use std::{
    fmt::Debug,
    fs::File,
    io::{stdin, Cursor, Read},
};
use structopt::StructOpt;

fn main() -> Result<()> {
    let options = Options::from_args();

    let decoded = decode_dap_message(&options.message_file, &options.media_type)?;
    println!("{decoded:#?}");

    Ok(())
}

/// Decode the contents of `message_file` as a DAP message with `media_type`, returning the decoded
/// object.
fn decode_dap_message(message_file: &str, media_type: &str) -> Result<Box<dyn Debug>> {
    let mut reader = if message_file.eq("-") {
        Box::new(stdin()) as Box<dyn Read>
    } else {
        Box::new(File::open(message_file)?) as Box<dyn Read>
    };

    let mut message_buf = Vec::new();
    reader.read_to_end(&mut message_buf)?;

    let mut binary_message = Cursor::new(message_buf.as_slice());

    let decoded = match media_type {
        "hpke-config" => Box::new(HpkeConfig::decode(&mut binary_message)?) as Box<dyn Debug>,
        "report" => Box::new(Report::decode(&mut binary_message)?) as Box<dyn Debug>,
        "aggregate-job-put" => Box::new(AggregateJobPutReq::<TimeInterval>::decode(
            &mut binary_message,
        )?) as Box<dyn Debug>,
        "aggregate-job" => Box::new(AggregateJob::decode(&mut binary_message)?) as Box<dyn Debug>,
        "aggregate-share-req" => Box::new(AggregateShareReq::<TimeInterval>::decode(
            &mut binary_message,
        )?) as Box<dyn Debug>,
        "aggregate-share-resp" => {
            Box::new(AggregateShareResp::decode(&mut binary_message)?) as Box<dyn Debug>
        }
        "collect-req" => {
            Box::new(CollectReq::<TimeInterval>::decode(&mut binary_message)?) as Box<dyn Debug>
        }
        "collect-resp" => {
            Box::new(CollectResp::<TimeInterval>::decode(&mut binary_message)?) as Box<dyn Debug>
        }
        _ => return Err(anyhow!("unknown media type")),
    };

    Ok(decoded)
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "dap-decode",
    about = "Distributed Aggregation Protocol message decoder",
    rename_all = "kebab-case",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Options {
    /// Path to file containing message to decode. Pass "-" to read from stdin.
    message_file: String,

    /// Media type of the message to decode.
    #[structopt(long, short = "t", required = true, possible_values(&[
            "hpke-config",
            "report",
            "aggregate-job-put",
            "aggregate-job",
            "aggregate-share-req",
            "aggregate-share-resp",
            "collect-req",
            "collect-resp",
        ]))]
    media_type: String,
}
