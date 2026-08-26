// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared authenticated VM boundary transport.
//!
//! Hypervisor drivers provision a VM and mint a [`VmTopology`]. The logical
//! supervisor remains on the host and drives the RFC 0012 lifecycle through
//! [`VmHostBackend`]. Inside the guest, [`run_guest`] invokes the existing
//! `openshell-supervisor-process` implementation; this crate does not define a
//! second supervisor or agent model.

mod backend;
mod guest;
mod protocol;

pub use backend::{VmHostBackend, VmTopology, VmTransport};
pub use guest::{GuestConfig, run_guest};
