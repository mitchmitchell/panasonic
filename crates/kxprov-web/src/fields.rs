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

pub const UNKNOWN_TABLE_ERROR: &str = "That phone table does not exist.";

pub fn record_range_error(table: u8, first: u16, last: u16) -> String {
    format!("Enter a whole number from {first} to {last} for table {table}.")
}

pub fn record_range_help() -> String {
    let mut tables: Vec<u8> = FieldKind::ALL.iter().map(|k| k.table()).collect();
    tables.sort_unstable();
    tables.dedup();
    let ranges: Vec<String> = tables
        .into_iter()
        .filter_map(|t| {
            let (first, last) = kxtd1232::tables::spec(t)?.label_range()?;
            Some(format!("table {t} from {first} to {last}"))
        })
        .collect();
    format!("Which record in that table: {}.", ranges.join(", "))
}

pub fn parse_record_input(table: u8, raw: &str) -> Result<u16, String> {
    let spec = kxtd1232::tables::spec(table).ok_or_else(|| UNKNOWN_TABLE_ERROR.to_string())?;
    let (first, last) = spec
        .label_range()
        .ok_or_else(|| UNKNOWN_TABLE_ERROR.to_string())?;
    raw.trim()
        .parse::<u16>()
        .ok()
        .and_then(|label| spec.label_to_index(label))
        .ok_or_else(|| record_range_error(table, first, last))
}

pub fn record_label(table: u8, index: u16) -> u16 {
    kxtd1232::tables::spec(table).map_or(index, |s| s.index_to_label(index))
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
    fn record_bounds_follow_the_table() {
        let last = FieldKind::CidNumber.records() - 1;
        assert_eq!(parse_record_input(36, "0"), Ok(0));
        assert_eq!(parse_record_input(36, &format!(" {last} ")), Ok(last));
        let err = record_range_error(36, 0, last);
        for bad in [
            format!("{}", last + 1),
            "abc".into(),
            "1.0".into(),
            "-1".into(),
            String::new(),
            "65536".into(),
        ] {
            assert_eq!(parse_record_input(36, &bad), Err(err.clone()), "{bad:?}");
        }
        assert_eq!(
            parse_record_input(11, "0"),
            Err(UNKNOWN_TABLE_ERROR.to_string())
        );
    }
}
