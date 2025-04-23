use anyhow::{Result, Context};
use clap::Args;
use std::fs;
use tracing::info;
use inquire::Select;
use reqwest;
use std::io::Write;

#[derive(Args)]
pub struct NewArgs {
    /// Name of the project to create
    #[arg(short, long, required=true)]
    name: String,
}

#[derive(Clone)]
enum Template {
    HelloWorld,
    EthPrice,
}

impl std::fmt::Display for Template {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Template::HelloWorld => write!(f, "Hello World"),
            Template::EthPrice => write!(f, "ETH Price"),
        }
    }
}

async fn download_template(template: &Template, project_path: &std::path::Path) -> Result<()> {
    let base_url = "https://raw.githubusercontent.com/marlinprotocol/oyster-serverless-templates/master";
    
    let template_url = match template {
        Template::HelloWorld => format!("{}/hello-world/worker.js", base_url),
        Template::EthPrice => format!("{}/eth-price/worker.js", base_url),
    };

    let response = reqwest::get(&template_url)
        .await
        .context("Failed to download template")?
        .text()
        .await
        .context("Failed to read template content")?;

    let worker_path = project_path.join("worker.js");
    let mut file = fs::File::create(&worker_path)
        .context("Failed to create worker.js")?;
    
    file.write_all(response.as_bytes())
        .context("Failed to write template content")?;

    Ok(())
}

pub async fn run_new(args: NewArgs) -> Result<()> {
    let project_path = std::env::current_dir()?.join(&args.name);
    fs::create_dir_all(&project_path)?;
    
    let templates = vec![Template::HelloWorld, Template::EthPrice];
    
    let template = Select::new("Select a starter template:", templates)
        .prompt()
        .context("Failed to select template")?;

    download_template(&template, &project_path).await?;
    
    info!("Created new project at {}", project_path.display());
    Ok(())
}