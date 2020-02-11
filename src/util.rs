use std::time::{SystemTime, UNIX_EPOCH};

use serde::ser::SerializeStruct;

pub fn serialize_system_time<S>(ts: &SystemTime, ser: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let elapsed = ts.elapsed().unwrap();
    if let Ok(dur) = ts.duration_since(UNIX_EPOCH) {
        let mut f = ser.serialize_struct("time", 2)?;
        f.serialize_field("ts", &dur.as_secs_f64())?;
        f.serialize_field("ago", &elapsed.as_secs_f64())?;
        f.end()
    } else {
        ser.serialize_str("unknown")
    }
}
