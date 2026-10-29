// Copyright 2010-2024 The ZAP Development Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file is a Rust derivative of the ZAP OpenAPI add-on. It changes the
// language and the architecture (Apache License 2.0, section 4). It is not
// an official OWASP ZAP build.

//! A small OpenAPI document becomes the expected URLs and methods.

use std::path::Path;

use http::Method;

use crate::{import_path, import_str, spider_seeds, ImportError};

const PETS_YAML: &str = r##"
openapi: 3.0.3
info:
  title: Pets
  version: "1.0.0"
servers:
  - url: http://{host}/v1
    variables:
      host:
        default: petstore.example
paths:
  /pets:
    get:
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
            example: 10
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/NewPet"
  /pets/{petId}:
    get:
      parameters:
        - $ref: "#/components/parameters/PetId"
components:
  parameters:
    PetId:
      name: petId
      in: path
      required: true
      schema:
        type: string
        example: abc
  schemas:
    NewPet:
      type: object
      properties:
        name:
          type: string
          example: fido
"##;

const PETS_V2: &str = r#"{
  "swagger": "2.0",
  "info": {"title": "Pets", "version": "1.0.0"},
  "host": "petstore.example",
  "basePath": "/v1",
  "schemes": ["https"],
  "paths": {
    "/pets": {
      "get": {
        "parameters": [
          {"name": "status", "in": "query", "type": "string", "enum": ["available", "sold"]}
        ]
      },
      "post": {
        "parameters": [
          {
            "name": "body",
            "in": "body",
            "schema": {
              "type": "object",
              "properties": {"name": {"type": "string", "example": "fido"}}
            }
          }
        ]
      }
    },
    "/pets/{id}": {
      "delete": {
        "parameters": [
          {"name": "id", "in": "path", "required": true, "type": "integer"}
        ]
      }
    }
  }
}"#;

fn pairs(document: &str) -> Vec<(String, String)> {
    import_str(document, None)
        .unwrap()
        .into_iter()
        .map(|request| (request.method, request.url))
        .collect()
}

#[test]
fn openapi3_yaml_lists_methods_and_urls() {
    let requests = import_str(PETS_YAML, None).unwrap();
    assert_eq!(
        pairs(PETS_YAML),
        vec![
            (
                "GET".to_string(),
                "http://petstore.example/v1/pets?limit=10".to_string()
            ),
            (
                "POST".to_string(),
                "http://petstore.example/v1/pets".to_string()
            ),
            (
                "GET".to_string(),
                "http://petstore.example/v1/pets/abc".to_string()
            ),
        ]
    );
    assert_eq!(requests[1].body, r#"{"name":"fido"}"#);
    assert_eq!(
        requests[1].content_type.as_deref(),
        Some("application/json")
    );
    let message = requests[1].active_scan_message();
    assert_eq!(message.method, Method::POST);
    assert_eq!(message.uri.to_string(), "http://petstore.example/v1/pets");
    assert_eq!(&message.body[..], br#"{"name":"fido"}"#);
    assert_eq!(
        spider_seeds(&requests),
        vec![
            "http://petstore.example/v1/pets?limit=10".to_string(),
            "http://petstore.example/v1/pets".to_string(),
            "http://petstore.example/v1/pets/abc".to_string(),
        ]
    );
}

#[test]
fn swagger2_json_lists_methods_and_urls() {
    assert_eq!(
        pairs(PETS_V2),
        vec![
            (
                "GET".to_string(),
                "https://petstore.example/v1/pets?status=available".to_string()
            ),
            (
                "POST".to_string(),
                "https://petstore.example/v1/pets".to_string()
            ),
            (
                "DELETE".to_string(),
                "https://petstore.example/v1/pets/1".to_string()
            ),
        ]
    );
    let requests = import_str(PETS_V2, None).unwrap();
    assert_eq!(requests[1].body, r#"{"name":"fido"}"#);
    let message = requests[2].active_scan_message();
    assert_eq!(message.method, Method::DELETE);
    assert_eq!(
        message.uri.to_string(),
        "https://petstore.example/v1/pets/1"
    );
}

#[test]
fn shared_url_is_one_spider_seed_and_two_methods() {
    let document = r##"
openapi: "3.0.0"
info: {title: t, version: "1"}
servers:
  - url: http://petstore.example
paths:
  /health:
    get: {}
    put: {}
"##;
    let requests = import_str(document, None).unwrap();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.method.as_str())
            .collect::<Vec<_>>(),
        ["GET", "PUT"]
    );
    assert_eq!(
        spider_seeds(&requests),
        ["http://petstore.example/health".to_string()]
    );
    assert_eq!(requests[0].spider_seed(), "http://petstore.example/health");
    assert_eq!(requests[1].active_scan_message().method, Method::PUT);
}

#[test]
fn target_replaces_the_server_url() {
    let requests = import_str(PETS_YAML, Some("http://127.0.0.1:8080/api/")).unwrap();
    assert_eq!(requests[0].url, "http://127.0.0.1:8080/api/pets?limit=10");
}

#[test]
fn relative_server_without_target_is_rejected() {
    let document = r##"
openapi: 3.0.0
info: {title: t, version: "1"}
servers:
  - url: /v1
paths:
  /pets:
    get: {}
"##;
    let err = import_str(document, None).unwrap_err();
    assert!(matches!(err, ImportError::NoServer));
}

#[test]
fn import_path_reads_a_local_yaml_file() {
    let path = std::env::temp_dir().join(format!("zap-openapi-{}-pets.yaml", std::process::id()));
    std::fs::write(&path, PETS_YAML).unwrap();
    let requests = import_path(&path, None).unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].url, "http://petstore.example/v1/pets?limit=10");
}

#[test]
fn missing_file_is_an_error() {
    let err = import_path(Path::new("missing-openapi-definition.yaml"), None).unwrap_err();
    assert!(err.to_string().contains("missing-openapi-definition.yaml"));
}

#[test]
fn empty_and_unknown_documents_fail() {
    assert!(matches!(
        import_str("   ", None).unwrap_err(),
        ImportError::Empty
    ));
    assert!(matches!(
        import_str("{", None).unwrap_err(),
        ImportError::Syntax(_)
    ));
    assert!(matches!(
        import_str("{\"info\":{}}", None).unwrap_err(),
        ImportError::Unsupported
    ));
    assert!(matches!(
        import_str(PETS_YAML, Some("ftp://files.example/spec")).unwrap_err(),
        ImportError::BadTarget(_)
    ));
}
