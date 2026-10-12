#version 450
// Fragment shader for tests/fixtures/external/spirv/shader.spv: a uniform
// block, a sampler, comparisons (OpFOrdLessThan, OpSLessThan), a loop and
// a branch, so the listing shows a spread of opcodes.
layout(location = 0) in vec2 uv;
layout(location = 0) out vec4 color;
layout(binding = 0) uniform Params {
    vec4 tint;
    float threshold;
    int steps;
} params;
layout(binding = 1) uniform sampler2D tex;

void main() {
    vec4 c = texture(tex, uv) * params.tint;
    for (int i = 0; i < params.steps; i++) {
        c.rgb *= 0.5;
    }
    if (c.a < params.threshold) {
        discard;
    }
    color = c;
}
