/* Small normal and transient control-flow fixture for the combined PAC+BTI mode. */
int marker_counter;

__attribute__((noinline)) int marker_step(int value) {
    if (value & 1)
        marker_counter += value;
    else
        marker_counter -= value;
    return marker_counter;
}

int main(void) {
    return marker_step(3);
}
