public class Hello {
    public static void main(String[] args) throws Exception {
        Thread worker = new Thread(() -> {
            long sum = 0;
            for (int i = 0; i < 1000; i++) { sum += i; }
            System.out.println("sum " + sum);
        }, "worker");
        worker.start();
        worker.join();
        System.gc();
    }
}
