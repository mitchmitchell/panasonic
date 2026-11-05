use kxprov_mock::ReadOnlyPbxClient;

fn unwrap(client: ReadOnlyPbxClient) -> impl Sized {
    client.inner
}

fn main() {
    drop(unwrap);
}
