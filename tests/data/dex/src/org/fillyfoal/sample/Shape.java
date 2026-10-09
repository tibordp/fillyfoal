package org.fillyfoal.sample;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.ArrayList;
import java.util.List;

/** Test classes for the DEX fixture: interfaces, enums, annotations,
 * generics, inner classes, static values, exceptions and switches. */
public interface Shape {
    double area();

    default String describe() {
        return getClass().getSimpleName() + " with area " + area();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD, ElementType.PARAMETER})
    @interface Info {
        String value() default "";
        int version() default 1;
        Kind kind() default Kind.PLAIN;
        String[] tags() default {};
        Class<?> owner() default Object.class;
    }

    enum Kind { PLAIN, ROUND, POINTY }

    @Info(value = "circle", version = 2, kind = Kind.ROUND, tags = {"a", "b"}, owner = Circle.class)
    final class Circle implements Shape, Comparable<Circle> {
        public static final double PI = 3.141592653589793;
        public static final String UNIT = "cm";
        public static final long BIG = 1L << 40;
        static final char MARK = 'c';
        static final byte SMALL = -5;
        static final boolean ROUND = true;
        @Info("radius") private final double radius;

        public Circle(@Info("r") double radius) {
            if (radius < 0) {
                throw new IllegalArgumentException("negative radius: " + radius);
            }
            this.radius = radius;
        }

        @Override
        @Info(value = "area", version = 3)
        public double area() {
            return PI * radius * radius;
        }

        @Override
        public int compareTo(Circle other) {
            return Double.compare(radius, other.radius);
        }
    }

    abstract class Polygon implements Shape {
        protected final List<double[]> points = new ArrayList<>();

        protected Polygon add(double x, double y) {
            points.add(new double[] {x, y});
            return this;
        }

        public int corners() {
            return points.size();
        }
    }

    class Square extends Polygon {
        private final double side;

        public Square(double side) {
            this.side = side;
            add(0, 0).add(side, 0).add(side, side).add(0, side);
        }

        @Override
        public double area() {
            return side * side;
        }

        public static Kind classify(int corners) {
            switch (corners) {
                case 0: return Kind.ROUND;
                case 3: case 4: case 5: return Kind.POINTY;
                default: return Kind.PLAIN;
            }
        }

        public static int parse(String text) {
            try {
                return Integer.parseInt(text.trim());
            } catch (NumberFormatException e) {
                return -1;
            } finally {
                Counter.count++;
            }
        }

        static class Counter {
            static int count;
            static synchronized int next() {
                return ++count;
            }
        }
    }
}
