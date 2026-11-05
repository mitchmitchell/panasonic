use kxprov_api::{DiffHash, PlanId};
use kxprov_mock::{CallerIdentity, ReadOnlyPbxClient};

async fn try_apply(client: ReadOnlyPbxClient, caller: CallerIdentity) {
    client
        .apply_plan(&caller, PlanId("p".into()), DiffHash("d".into()))
        .await
        .unwrap();
}

fn main() {
    drop(try_apply);
}
