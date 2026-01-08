package com.prodguard.checks.catalog;

import com.prodguard.core.CheckDescriptor;
import com.prodguard.core.ProdCheck;
import org.junit.jupiter.api.Test;
import org.reflections.Reflections;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class ChecksCatalogGeneratorTest {

    @Test
    void generateChecksCatalogMarkdown() throws Exception {

        Reflections reflections =
                new Reflections("com.prodguard.checks.free");

        Set<Class<? extends ProdCheck>> checkClasses =
                reflections.getSubTypesOf(ProdCheck.class);

        List<CheckDescriptor> descriptors =
                checkClasses.stream()
                        .map(ChecksCatalogGeneratorTest::readDescriptor)
                        .sorted(Comparator.comparing(CheckDescriptor::code))
                        .collect(Collectors.toList());

        String markdown = renderMarkdownBasic(descriptors);

        Path output = Path.of("CHECKS.md");
        Files.writeString(output, markdown);
    }

    private static CheckDescriptor readDescriptor(
            Class<? extends ProdCheck> checkClass) {

        try {
            Field field = checkClass.getDeclaredField("DESCRIPTOR");
            field.setAccessible(true);
            return (CheckDescriptor) field.get(null);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to read DESCRIPTOR from " + checkClass.getName(), e
            );
        }
    }

    private static String renderMarkdownBasic(
            List<CheckDescriptor> descriptors) {

        StringBuilder md = new StringBuilder();

        md.append("# ProdGuard – Checks Catalog\n\n");
        md.append("This document is generated automatically from the source code.\n");
        md.append("Do not edit manually.\n\n");

        md.append("## Available Checks\n\n");
        md.append("| Code | Name | Default Severity | tier |\n");
        md.append("|------|------|------------------|------|\n");

        for (CheckDescriptor d : descriptors) {
            md.append("| ")
              .append(d.code()).append(" | ")
              .append(d.name()).append(" | ")
              .append(d.severity()).append(" | ")
              .append(d.tier()).append(" |\n");
        }

        md.append("\n");

        return md.toString();
    }
    
    private static String renderMarkdownWithLongDescriptions(
            List<CheckDescriptor> descriptors) {

        StringBuilder md = new StringBuilder();

        md.append("# ProdGuard – Checks Catalog\n\n");
        md.append("This document is generated automatically from the source code.\n");
        md.append("Do not edit manually.\n\n");

        md.append("## Available Checks\n\n");
        md.append("| Code | Name | Default Severity | tier  \n");
        md.append("|------|------|------------------|------|\n");

        for (CheckDescriptor d : descriptors) {
            md.append("| ")
              .append(d.code()).append(" | ")
              .append(d.name()).append(" | ")
              .append(d.severity()).append(" | ")
              .append(d.tier()).append(" |\n");
        }

        md.append("\n---\n\n");

        for (CheckDescriptor d : descriptors) {
            if (d.hasLongDescription()) {
                md.append("## ")
                  .append(d.code())
                  .append(" – ")
                  .append(d.name())
                  .append("\n\n");

                md.append(d.longDescription().trim())
                  .append("\n\n");
            }
        }

        return md.toString();
    }

    
}
