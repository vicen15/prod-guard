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

public class WebDocsGeneratorTest {

    @Test
    void generateStaticWebDocs() throws Exception {

        Reflections reflections =
                new Reflections("com.prodguard.checks.free");

        Set<Class<? extends ProdCheck>> checkClasses =
                reflections.getSubTypesOf(ProdCheck.class);

        List<CheckDescriptor> descriptors =
                checkClasses.stream()
                        .map(WebDocsGeneratorTest::readDescriptor)
                        .sorted(Comparator.comparing(CheckDescriptor::code))
                        .collect(Collectors.toList());

        Path docsDir = Path.of("docs");
        Path checksDir = docsDir.resolve("checks");

        Files.createDirectories(checksDir);

        Files.writeString(
                docsDir.resolve("index.html"),
                renderIndex(descriptors)
        );

        for (CheckDescriptor d : descriptors) {
            Files.writeString(
                    checksDir.resolve(d.code() + ".html"),
                    renderCheckPage(d)
            );
        }
    }

    private static CheckDescriptor readDescriptor(
            Class<? extends ProdCheck> checkClass) {

        try {
            Field field = checkClass.getDeclaredField("DESCRIPTOR");
            field.setAccessible(true);
            return (CheckDescriptor) field.get(null);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String renderIndex(List<CheckDescriptor> descriptors) {
        StringBuilder html = new StringBuilder();

        html.append("""
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="UTF-8">
              <title>ProdGuard – Checks</title>
              <style>
                body { font-family: sans-serif; padding: 2rem; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ccc; padding: 8px; }
                th { background: #f5f5f5; }
              </style>
            </head>
            <body>
            <h1>ProdGuard – Checks Catalog</h1>
            <table>
              <tr>
                <th>Code</th>
                <th>Name</th>
                <th>Severity</th>
                <th>Tier</th>
              </tr>
            """);

        for (CheckDescriptor d : descriptors) {
        	html.append("""
        		    <tr>
        		      <td><a href="checks/%s.html">%s</a></td>
        		      <td>%s</td>
        		      <td>%s</td>
        		      <td>%s</td>
        		    </tr>
        		    """.formatted(
        		        d.code(),
        		        d.code(),
        		        d.name(),
        		        d.severity(),
        		        d.tier()
        		    ));
        }

        html.append("""
            </table>
            </body>
            </html>
            """);

        return html.toString();
    }

    private static String renderCheckPage(CheckDescriptor d) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="UTF-8">
              <title>%s – %s</title>
              <style>
                body { font-family: sans-serif; padding: 2rem; max-width: 800px; }
                .severity { font-weight: bold; }
              </style>
            </head>
            <body>
              <h1>%s – %s</h1>
              <p class="severity">Default severity: %s ---- Tier: %s</p>
              <hr/>
              <div>
                %s
              </div>
            </body>
            </html>
            """.formatted(
                d.code(),
                d.name(),
                d.code(),
                d.name(),
                d.severity(),
                d.tier(),
                d.hasLongDescription()
                    ? d.longDescription().replace("\n", "<br/>")
                    : "<em>No extended description available.</em>"
        );
    }
}
