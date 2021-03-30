use std::fmt;
use std::ops::{Deref, DerefMut};

use super::ShItem;

pub struct ParamItem {
    primary_id: String,
    parameters: Vec<(String, Option<ShItem>)>,
}

pub struct ShParamList(Vec<ParamItem>);

impl ParamItem {
    pub fn new(primary_id: String) -> Self {
        ParamItem {
            primary_id,
            parameters: Vec::new(),
        }
    }
}

impl ShParamList {
    pub fn new() -> Self {
        ShParamList(Vec::new())
    }
}

impl Deref for ParamItem {
    type Target = Vec<(String, Option<ShItem>)>;
    fn deref(&self) -> &Self::Target {
        &self.parameters
    }
}

impl DerefMut for ParamItem {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.parameters
    }
}

impl Deref for ShParamList {
    type Target = Vec<ParamItem>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ShParamList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// https://tools.ietf.org/html/draft-ietf-httpbis-header-structure-10#section-4.1.4
impl fmt::Display for ShParamList {
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

