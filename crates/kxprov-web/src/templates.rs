use askama::Template;

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub page_title: String,
    pub show_error: bool,
    pub error: String,
    pub csrf_token: String,
}

pub struct ReadFieldRow {
    pub name: String,
    pub value: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub show_mode_banner: bool,
    pub mode_banner: String,
    pub mode_banner_class: String,
    pub show_profile_badge: bool,
    pub profile_badge: String,
    pub profile_badge_class: String,
    pub show_status: bool,
    pub locked: bool,
    pub queue_depth: u32,
    pub table_value: String,
    pub record_value: String,
    pub field_value: String,
    pub new_value_value: String,
    pub show_read_form_error: bool,
    pub read_form_error: String,
    pub show_read_result: bool,
    pub read_table: u8,
    pub read_record: u16,
    pub read_fields: Vec<ReadFieldRow>,
    pub show_plan_form_error: bool,
    pub plan_form_error: String,
    pub show_plan: bool,
    pub plan_id_hex: String,
    pub diff_hash_hex: String,
    pub plan_id_prefix: String,
    pub plan_summary: String,
    pub plan_table: u8,
    pub plan_record: u16,
    pub plan_field: String,
    pub plan_old_value: String,
    pub plan_new_value: String,
    pub show_production_plan_hint: bool,
    pub plan_expires_at_iso: String,
    pub plan_expires_at_chicago: String,
    pub plan_expires_at_ms: String,
    pub csrf_token: String,
}
