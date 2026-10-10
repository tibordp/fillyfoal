//! Machine-learning model formats: protobuf-based (ONNX, Core ML,
//! TensorFlow, SentencePiece, TFRecord), FlatBuffers-based (TensorFlow Lite,
//! ONNX Runtime, ExecuTorch), llama.cpp's pre-GGUF GGML files, framework
//! binaries (ncnn, MXNet, NNEF, fastText, MLIR bytecode) and text model
//! descriptions (Caffe, Darknet, OpenVINO, PMML, LIBSVM, ...).
//!
//! GGUF model files live in `gguf`.

pub mod binary;
pub mod gguf;
pub mod protos;
pub mod text;
pub mod tflite;
