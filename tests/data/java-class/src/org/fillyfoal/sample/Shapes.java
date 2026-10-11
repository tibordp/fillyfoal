package org.fillyfoal.sample;

import java.util.List;
import java.util.function.Function;

/**
 * Pattern switches (typeSwitch bootstrap), lambdas and method references
 * (LambdaMetafactory), string concatenation (StringConcatFactory), loops and
 * branches (StackMapTable), a try/catch (exception table), generics
 * (Signature) and parameter / type annotations.
 */
public final class Shapes {
    private static final int LIMIT = 1000;

    private Shapes() {}

    static String describe(Shape s) {
        return switch (s) {
            case Shape.Circle c when c.radius() == 0 -> "point";
            case Shape.Circle c -> "circle of radius " + c.radius();
            case Shape.Rect(double w, double h) -> "rect " + w + "x" + h;
        };
    }

    static int code(String name) {
        switch (name) {
            case "circle":
                return 1;
            case "rect":
                return 2;
            default:
                return 0;
        }
    }

    static int bucket(int n) {
        switch (n) {
            case 1: case 2: case 3: case 4:
                return n * 10;
            case 100:
                return -1;
            case 5000:
                return -2;
            default:
                return n < 0 ? 0 : LIMIT;
        }
    }

    static double total(List<? extends Shape> shapes) {
        double sum = 0;
        for (Shape s : shapes) {
            sum += s.area();
        }
        return sum;
    }

    static <T extends Shape> List<String> names(List<T> shapes, Function<? super T, String> f) {
        return shapes.stream().map(f).filter(x -> !x.isEmpty()).toList();
    }

    static long parse(@Tag("text") String text) {
        try {
            return Long.parseLong(text);
        } catch (NumberFormatException e) {
            return -1L;
        }
    }

    static @Tag("result") String first(List<@Tag("item") String> items) {
        return items.isEmpty() ? null : items.get(0);
    }

    public static void main(String[] args) {
        List<Shape> shapes = List.of(new Shape.Circle(1.5), new Shape.Rect(2, 3));
        System.out.println(total(shapes));
        System.out.println(names(shapes, Shapes::describe));
        System.out.println(code(args.length > 0 ? args[0] : "rect") + bucket(args.length));
    }
}
