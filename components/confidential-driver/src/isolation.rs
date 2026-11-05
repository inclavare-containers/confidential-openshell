// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reuse native boundary provisioning and network policy.

#[path = "../../../repos/openshell/crates/openshell-driver-kubernetes/src/isolation.rs"]
mod upstream;
pub use upstream::*;
