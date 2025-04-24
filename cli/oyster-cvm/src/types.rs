use clap::ValueEnum;

#[derive(Debug, Clone)]
pub enum Platform {
    AMD64,
    ARM64,
}

impl Platform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::AMD64 => "amd64",
            Platform::ARM64 => "arm64",
        }
    }

    pub fn nix_arch(&self) -> &'static str {
        match self {
            Platform::AMD64 => "x86_64-linux",
            Platform::ARM64 => "aarch64-linux",
        }
    }

    pub fn base_dev_image(&self) -> &'static str {
        match self {
            Platform::AMD64 => "marlinorg/local-dev-image@sha256:6b65a799a20eef7dba4cf637933075d32334456aeee7d994ebbc5d914cf46eec",
            Platform::ARM64 => "marlinorg/local-dev-image@sha256:63c780fd06a46889ad6fbca77105fb681e87014c48ec96cb7e0a729190a00b8c",
        }
    }
}

impl ValueEnum for Platform {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::AMD64, Self::ARM64]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(self.as_str().into())
    }
}

#[derive(Debug)]
pub enum Dependency {
    Docker,
    Nix,
}

impl Dependency {
    pub fn command(&self) -> &'static str {
        match self {
            Dependency::Docker => "docker",
            Dependency::Nix => "nix",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Dependency::Docker => "Docker",
            Dependency::Nix => "Nix",
        }
    }

    pub fn install_url(&self) -> &'static str {
        match self {
            Dependency::Docker => "https://docs.docker.com/engine/install/",
            Dependency::Nix => "https://github.com/DeterminateSystems/nix-installer",
        }
    }
}

#[derive(Debug, Clone)]
pub enum StorageProvider {
    Pinata,
}

impl StorageProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            StorageProvider::Pinata => "pinata",
        }
    }
}
