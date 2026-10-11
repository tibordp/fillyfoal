package org.fillyfoal.sample;

/** A sealed hierarchy of records: PermittedSubclasses, Record, NestMembers. */
@Tag(value = "shape", level = Tag.Level.HIGH, aliases = {"form", "figure"})
public sealed interface Shape permits Shape.Circle, Shape.Rect {
    double area();

    record Circle(@Tag("r") double radius) implements Shape {
        public Circle {
            if (radius < 0) {
                throw new IllegalArgumentException("radius " + radius);
            }
        }

        @Override
        public double area() {
            return Math.PI * radius * radius;
        }
    }

    record Rect(double w, double h) implements Shape {
        @Override
        public double area() {
            return w * h;
        }
    }
}
