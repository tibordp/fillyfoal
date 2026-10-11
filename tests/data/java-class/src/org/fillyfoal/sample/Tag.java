package org.fillyfoal.sample;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** A runtime annotation with defaults: AnnotationDefault per element. */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.PARAMETER, ElementType.RECORD_COMPONENT,
         ElementType.FIELD, ElementType.METHOD, ElementType.TYPE_USE})
public @interface Tag {
    enum Level { LOW, HIGH }

    String value() default "";

    Level level() default Level.LOW;

    String[] aliases() default {};

    int weight() default 1;
}
