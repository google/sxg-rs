use std::fmt;
use std::ops::{Deref, DerefMut};

use super::ShItem;

pub struct ParamItem<'a> {
    primary_id: &'a str,
    parameters: Vec<(&'a str, Option<ShItem<'a>>)>,
}

pub struct ShParamList<'a>(Vec<ParamItem<'a>>);

impl<'a> ParamItem<'a> {
    pub fn new(primary_id: &'a str) -> Self {
        ParamItem {
            primary_id,
            parameters: Vec::new(),
        }
    }
}

impl<'a> ShParamList<'a> {
    pub fn new() -> Self {
        ShParamList(Vec::new())
    }
}

impl<'a> Deref for ParamItem<'a> {
    type Target = Vec<(&'a str, Option<ShItem<'a>>)>;
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

