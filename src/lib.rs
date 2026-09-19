//! rotor — who reads a secret on a NixOS host, and does a rotation reach them?
//!
//! It reads a *built* system: the sops-nix manifest, the units of the host
//! and its containers, the files those units run, and the converge specs they
//! hand over. It never opens a secret; it knows names and paths only.

pub mod converge;
pub mod graph;
pub mod manifest;
pub mod scan;
