/** A module descriptor: the Module attribute. */
module org.fillyfoal.sample {
    requires java.base;
    requires static java.logging;
    exports org.fillyfoal.sample;
    opens org.fillyfoal.sample to java.logging;
    uses java.util.function.Function;
}
