// Copyright 2021 Google LLC
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

use std::borrow::Cow;
use std::fmt;
use std::ops::{Deref, DerefMut};

use super::ShItem;

#[derive(Debug)]
pub struct ParamItem<'a> {
    pub primary_id: Cow<'a, str>,
    pub parameters: Vec<(Cow<'a, str>, Option<ShItem<'a>>)>,
}

#[derive(Debug)]
pub struct ShParamList<'a>(pub Vec<ParamItem<'a>>);

impl<'a> ParamItem<'a> {
    pub fn new(primary_id: &'a str) -> Self {
        ParamItem {
            primary_id: primary_id.into(),
            parameters: Vec::new(),
        }
    }
}

impl<'a> ShParamList<'a> {
    pub fn new() -> Self {
        ShParamList(Vec::new())
    }
}

impl<'a> Default for ShParamList<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Deref for ParamItem<'a> {
    type Target = Vec<(Cow<'a, str>, Option<ShItem<'a>>)>;
    fn deref(&self) -> &Self::Target {
        &self.parameters
    }
}

impl<'a> DerefMut for ParamItem<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.parameters
    }
}

impl<'a> Deref for ShParamList<'a> {
    type Target = Vec<ParamItem<'a>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for ShParamList<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// https://tools.ietf.org/html/draft-ietf-httpbis-header-structure-10#section-4.1.4
impl<'a> fmt::Display for ShParamList<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, mem) in self.0.iter().enumerate() {
            write!(f, "{}", mem.primary_id)?;
            for (name, value) in mem.parameters.iter() {
                write!(f, ";")?;
                write!(f, "{}", name)?;
                if let Some(value) = value {
                    write!(f, "={}", value)?;
                }
            }
            if i < self.0.len() - 1 {
                write!(f, ", ")?;
            }
        }
        Ok(())
    }
}
