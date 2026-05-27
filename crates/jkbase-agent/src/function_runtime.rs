use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::info;
use wasmtime::*;
use bytes::Bytes;
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::p2::WasiCtxBuilder;
use wasmtime_wasi::preview1::WasiP1Ctx;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl FunctionResponse {
    pub fn error(status: u16, message: &str) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: message.as_bytes().to_vec(),
        }
    }
}

struct FunctionModule {
    engine: Engine,
    module: Module,
    linker: Linker<WasiP1Ctx>,
}

pub struct FunctionRuntime {
    functions: HashMap<String, Arc<FunctionModule>>,
}

impl FunctionRuntime {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
        }
    }

    pub fn load_module(&mut self, name: &str, wasm_path: &Path) -> Result<()> {
        let mut config = Config::new();
        config.consume_fuel(true);

        let engine = Engine::new(&config)?;
        let module = Module::from_file(&engine, wasm_path)
            .with_context(|| format!("failed to load WASM module from {}", wasm_path.display()))?;

        let mut linker = Linker::new(&engine);
        wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |ctx| ctx)?;

        info!(name, path = %wasm_path.display(), "loaded WASM function");

        self.functions.insert(
            name.to_string(),
            Arc::new(FunctionModule {
                engine,
                module,
                linker,
            }),
        );

        Ok(())
    }

    pub fn load_all_from_dir(&mut self, dir: &Path) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "wasm") {
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown");
                self.load_module(name, &path)?;
            }
        }

        Ok(())
    }

    pub fn has_function(&self, name: &str) -> bool {
        self.functions.contains_key(name)
    }

    pub fn list_functions(&self) -> Vec<String> {
        self.functions.keys().cloned().collect()
    }

    pub fn invoke(&self, name: &str, req: FunctionRequest) -> Result<FunctionResponse> {
        let func_mod = self
            .functions
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("function '{name}' not found"))?;

        let req_json = serde_json::to_vec(&req)?;

        let stdin = MemoryInputPipe::new(Bytes::from(req_json));
        let stdout = MemoryOutputPipe::new(1024 * 1024);
        let stderr = MemoryOutputPipe::new(64 * 1024);

        let stdout_clone = stdout.clone();
        let stderr_clone = stderr.clone();

        let wasi_ctx = WasiCtxBuilder::new()
            .stdin(stdin)
            .stdout(stdout)
            .stderr(stderr)
            .build_p1();

        let mut store = Store::new(&func_mod.engine, wasi_ctx);
        store.set_fuel(1_000_000_000)?;

        let instance = func_mod
            .linker
            .instantiate(&mut store, &func_mod.module)
            .context("failed to instantiate WASM module")?;

        let start = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .context("function must export '_start'")?;

        let result = start.call(&mut store, ());

        drop(store);

        let output = stdout_clone.contents();
        let err_output = stderr_clone.contents();

        tracing::debug!(
            function = name,
            stdout_len = output.len(),
            stderr_len = err_output.len(),
            "function execution complete"
        );

        if !err_output.is_empty() {
            let err_str = String::from_utf8_lossy(&err_output);
            tracing::warn!(function = name, stderr = %err_str, "function stderr output");
        }

        if let Err(e) = result {
            tracing::error!(function = name, error = %e, "function execution failed");
            return Ok(FunctionResponse::error(
                500,
                &format!("function error: {e}"),
            ));
        }

        if output.is_empty() {
            return Ok(FunctionResponse::error(
                500,
                "function produced no output",
            ));
        }

        let response: FunctionResponse = serde_json::from_slice(&output)
            .context("function output is not valid JSON response")?;

        Ok(response)
    }
}
