// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::time::Duration;

pub struct PoolingTimer(Duration);

const MIN_SLEEP: Duration = Duration::from_secs(60);
const MAX_SLEEP: Duration = Duration::from_secs(600);

impl PoolingTimer {
    pub fn new() -> Self {
        PoolingTimer(MIN_SLEEP)
    }
    pub async fn sleep(&mut self) {
        println!("Wait ACME server processing for {} seconds...", self.0.as_secs());
        tokio::time::sleep(self.0).await;
        self.0 *= 2;
        if self.0 > MAX_SLEEP {
            self.0 = MAX_SLEEP;
        }
    }
}
