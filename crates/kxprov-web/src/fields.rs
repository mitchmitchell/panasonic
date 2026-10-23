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

pub fn parse_record_input(raw: &str) -> Result<u16, String> {
    raw.trim()
        .parse()
        .map_err(|_| "record number must be a valid integer".to_string())
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
