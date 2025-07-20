# BinDiff-Server: Function Matching Engine with Binary Ninja Integration

**BinDiff-Server** is a modern, open-source binary diffing server inspired by Google’s [BinDiff](https://github.com/google/bindiff) 
and built as part of the [Google Summer of Code 2025](https://github.com/mandiant/flare-gsoc/blob/2025/doc/project-ideas.md#bindiff-rearchitect-binary-diff-server-and-port-to-pyqt) initiative.
It includes:

* A robust **C++ matching engine** powered by custom-built algorithms
* A [gRPC](https://grpc.io/)-based **client-server architecture**
* A cleanly integrated **Binary Ninja plugin** to allow easy usage by reverse engineers

---

## Table of Contents

- ### [Overview](#overview-1)


- ### [Architecture](#architecture-1)


- ### [Accuracy & Performance](#accuracy--performance-1)


- ### [Installation & Requirements](#installation--requirements-1)


- ### [Usage](#usage-1)


- ### [Extensibility](#extensibility-1)


- ### [Acknowledgments](#acknowledgments-1)

---

## Overview

This project implements a **function-level binary diffing engine** that analyzes `.BinExport` files and identifies matches between functions of two binaries. It is inspired by the academic foundations and algorithms behind Google BinDiff, but uses:

* **Custom algorithm implementations**
* **gRPC-based client-server model**
* **Python plugin for Binary Ninja**
* **Custom similarity and confidence scoring system**

---

## Architecture

### BinDiff Server (C++)

* Parses and caches uploaded `.BinExport` files
* Implements multiple **matching algorithms** implemented by us (name-based, hash-based, structural, neighborhood-aware, and more)
* Maintains a **diff cache** for repeated comparisons
* Provides match results with **similarity and confidence** scores, as well as **addresses and names of matched functions**

### Matching Algorithms

All matchers are custom-built in C++ and inspired by the logic described in [Google BinDiff papers](https://github.com/google/bindiff/tree/main/docs/papers). These include:

* **NameMatcher** (for debug builds)
* **HashMatcher** (raw byte hash)
* **MnemonicsPrimeHashMatcher**
* **BasicBlockStructureMatcher**
* **NeighbourhoodMatcher** (call graph-aware)
* and more...

Each matcher contributes to a weighted **similarity-confidence scoring system** designed to mimic the behavior and results of Google BinDiff.

### Binary Ninja Plugin (Python)

* Allows Binary Ninja users to:

	* Upload `.BinExport` files (generated via any supported plugin)
	* Select primary/secondary binaries to diff
	* View results with **matched/unmatched function names and addresses** as well as **overall summary of the diff**
* Communicates with the server using gRPC (via Python bindings)
* Presents results in a clean, Qt-based GUI panel

---

## Accuracy & Performance

* Achieves **\~90-98% match coverage** on average when compared to the official Google BinDiff on different kind of `.BinExport` files
* Custom similarity/confidence scoring was tuned empirically to closely match the output of the official tool

---

## Installation & Requirements

### Server (C++)

* Recommended OS: **Linux**
* Requirements:

	* `gRPC` (C++ bindings)
	* `protobuf` (v3+)
	* `CMake`
* If gRPC or protobuf paths are not detected automatically by your IDE:

	* You may need to specify the include/lib paths manually in your environment variables or CMake config.

### Binary Ninja Plugin (Python)

* Recommended OS: **Windows**
* Requirements:

	* Python 3.x
	* `grpcio`, `protobuf`
	* `PyQt5` (for UI rendering)
* Supported on **Binary Ninja 5.0+**
* Plugin folder can be dropped into the Binary Ninja `plugins/` folder.

	* The plugin will appear in the UI and allow interaction with the diff server.

---

## Usage

### 1. Generate `.BinExport` files

Use Binary Ninja or other supported tools to export `.BinExport` files from your binaries.

### 2. Upload to Server (via Plugin or CLI Client)

From the Binary Ninja plugin UI:

* Load a binary in Binary Ninja
* Upload the corresponding `.BinExport` file
* Mark it as *Primary* or *Secondary*

### 3. Run Diff

* Trigger the diff operation in the plugin
* Server computes matches and returns:

	* Matched function pairs (addresses & names)
	* Unmatched functions
	* Summary stats

---

## Extensibility

This project is modular and easy to extend. You can:

* Add new matchers by inheriting from `MatchingAlgorithm`
* Modify the scoring logic in the `BinDiffEngine`
* Add block-matching mechanism by creating a model class called `Block` 
and implementing similar matching algorithms which are already written for function matching
* Customize the Binary Ninja plugin UI

---

## Acknowledgments

* Based on [Google Summer of Code 2025](https://github.com/mandiant/flare-gsoc/blob/2025/doc/project-ideas.md#bindiff-rearchitect-binary-diff-server-and-port-to-pyqt) research.
* Inspired by the [Google BinExport](https://github.com/google/binexport) & [BinDiff](https://github.com/google/bindiff) repositories
* Thanks to [Binary Ninja](https://api.binary.ninja/) for providing plugin infrastructure and easily understandable API.
