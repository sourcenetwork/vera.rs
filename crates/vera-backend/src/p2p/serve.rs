use super::*;
use commonware_storage::{merkle::MAX_PROOF_DIGESTS_PER_ELEMENT, qmdb};

const READ_AHEAD: u64 = 8;
const PROOF_BUDGET: usize = MAX_FETCH_OPS.get() as usize * MAX_PROOF_DIGESTS_PER_ELEMENT * 32 + 32;

/// Inspect bounded chunks; Commonware's public range API also generates their proofs.
pub(super) async fn response<DB: Partition>(
    db: &DB,
    request: Request<mmr::Family>,
) -> Result<Response<mmr::Family, DB::Op, Digest>, qmdb::Error<mmr::Family>> {
    let Request::Operations {
        size,
        start,
        max_ops,
    } = request
    else {
        return checked::<DB>(db.serve(request).await?.0);
    };
    let limit = max_ops.get().min((*size).saturating_sub(*start));
    let mut count = 0;
    let mut bytes = 0;
    loop {
        let chunk_limit =
            NonZeroU64::new(limit.saturating_sub(count).min(READ_AHEAD)).unwrap_or(NonZeroU64::MIN);
        let chunk = db
            .serve(Request::Operations {
                size,
                start: start.saturating_add(count),
                max_ops: chunk_limit,
            })
            .await?
            .0;
        let Response::Operations { operations, .. } = &chunk else {
            unreachable!("operation request returned a boundary response");
        };
        if operations.iter().any(|op| !DB::accepts(op)) {
            return Err(qmdb::Error::DataCorrupted(
                "operation exceeds peer codec limits",
            ));
        }
        if count == 0
            && operations.len() as u64 == limit
            && chunk.encode_size() <= MAX_RESPONSE_BYTES
        {
            return Ok(chunk);
        }
        let mut full = false;
        for operation in operations {
            let encoded = operation.encode_size();
            if encoded > MAX_RESPONSE_BYTES - PROOF_BUDGET - bytes {
                full = true;
                break;
            }
            bytes += encoded;
            count += 1;
        }
        if full || count == limit {
            break;
        }
    }
    let max_ops = NonZeroU64::new(count).ok_or(qmdb::Error::DataCorrupted(
        "partition operation exceeds sync response budget",
    ))?;
    checked::<DB>(
        db.serve(Request::Operations {
            size,
            start,
            max_ops,
        })
        .await?
        .0,
    )
}

fn checked<DB: Partition>(
    response: Response<mmr::Family, DB::Op, Digest>,
) -> Result<Response<mmr::Family, DB::Op, Digest>, qmdb::Error<mmr::Family>> {
    let valid = match &response {
        Response::Operations { operations, .. } => operations.iter().all(DB::accepts),
        Response::Boundary { op, .. } => DB::accepts(op),
    };
    if !valid {
        return Err(qmdb::Error::DataCorrupted(
            "operation exceeds peer codec limits",
        ));
    }
    if response.encode_size() > MAX_RESPONSE_BYTES {
        return Err(qmdb::Error::DataCorrupted(
            "partition sync response exceeds byte budget",
        ));
    }
    Ok(response)
}
