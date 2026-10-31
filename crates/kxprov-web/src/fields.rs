use kxtd1232::FieldKind;

pub fn parse_table_input(raw: &str) -> Result<u8, String> {
    let table_str = raw.trim();
    if let Some(hex) = table_str
        .strip_prefix("0x")
        .or_else(|| table_str.strip_prefix("0X"))
    {
        u8::from_str_radix(hex, 16).map_err(|_| "phone table must be a valid number".to_string())
    } else {
        table_str
            .parse::<u8>()
            .map_err(|_| "phone table must be a valid number".to_string())
    }
}

pub const RECORD_MIN: u16 = 1;
pub const RECORD_MAX: u16 = 9999;
pub const RECORD_INPUT_ERROR: &str = "Enter a whole number from 1 to 9999.";

pub fn parse_record_input(raw: &str) -> Result<u16, String> {
    raw.trim()
        .parse::<u16>()
        .ok()
        .filter(|record| (RECORD_MIN..=RECORD_MAX).contains(record))
        .ok_or_else(|| RECORD_INPUT_ERROR.to_string())
}

/// Rejects field names that are not in the table spec for the given table.
pub fn field_for_table(table: u8, field_name: &str) -> Result<FieldKind, String> {
    let kind = field_name
        .trim()
        .parse::<FieldKind>()
        .map_err(|_| "choose a supported field from the list".to_string())?;
    if kind.table() != table {
        return Err(format!(
            "{} is not valid for the phone table you chose",
            kind.name()
        ));
    }
    Ok(kind)
}

#[cfg(test)]
mod record_tests {
    use super::*;

    #[test]
    fn record_bounds() {
        assert_eq!(parse_record_input("1"), Ok(1));
        assert_eq!(parse_record_input(" 9999 "), Ok(9999));
        for bad in ["0", "10000", "abc", "1.0", "-1", "", "65536"] {
            assert_eq!(
                parse_record_input(bad),
                Err(RECORD_INPUT_ERROR.to_string()),
                "{bad:?}"
            );
        }
    }
}
