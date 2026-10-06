//! Machine-learning model formats: protobuf-based (ONNX, Core ML,
//! TensorFlow, SentencePiece, TFRecord), FlatBuffers-based (TensorFlow Lite,
//! ONNX Runtime, ExecuTorch), llama.cpp's pre-GGUF GGML files, framework
//! binaries (ncnn, MXNet, NNEF, fastText, MLIR bytecode) and text model
//! descriptions (Caffe, Darknet, OpenVINO, PMML, LIBSVM, ...).

pub mod proto;
pub mod protos;
pub mod flatbuf;
pub mod tflite;
