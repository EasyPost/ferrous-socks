use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::ser::SerializeStruct;

static ZERO_SECONDS: Duration = Duration::from_secs(0);

pub fn serialize_system_time<S>(ts: &SystemTime, ser: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let elapsed = ts.elapsed().unwrap_or(ZERO_SECONDS);
    if let Ok(dur) = ts.duration_since(UNIX_EPOCH) {
        let mut f = ser.serialize_struct("time", 2)?;
        f.serialize_field("ts", &dur.as_secs_f64())?;
        f.serialize_field("ago", &elapsed.as_secs_f64())?;
        f.end()
    } else {
        ser.serialize_str("unknown")
    }
}

#[cfg(test)]
mod tests {
    use super::serialize_system_time;
    use serde::Serialize;
    use std::time::{Duration, SystemTime};

    #[derive(Serialize)]
    struct Uut {
        #[serde(serialize_with = "serialize_system_time")]
        uut: SystemTime,
    }

    #[test]
    fn test_serialize_system_time() {
        let uut = Uut {
            uut: std::time::UNIX_EPOCH + Duration::from_secs(1642138333),
        };
        let found = serde_json::to_string(&uut).unwrap();
        assert!(found.contains(r#"{"uut":{"ts":1642138333.0,"ago":"#));
    }
}
