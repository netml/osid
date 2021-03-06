import java.io.*;
import java.util.ArrayList;

public class GA {
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BLACK = "\u001B[30m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ANSI_CYAN = "\u001B[36m";
    public static final String ANSI_WHITE = "\u001B[37m";

    public void execute(String weka_path, int classifier, String filename, int iteration, String work_folder, int no_of_features, int cross_validation, int population_size, String weights, int max_threads, int no_of_os_instances, String selected_features_file_path) {
        // Create an initial population
        GAPopulation myPop = new GAPopulation(population_size, true, no_of_features, weka_path, classifier, work_folder, weights, max_threads, no_of_os_instances);

        ArrayList<String> solutions = new ArrayList<String>();

        String solution = null;

        while (true) {
            solution = myPop.getFittest().toString();

            // Add the solution to the arraylist
            solutions.add(solution);

            // Print the solution
            int no_of_selected = 0;
            System.out.print(ANSI_RED + "Solution: " + ANSI_RESET);
            String tokens[] = solution.split("");

            // print bits in color
            for (int i = 0; i < tokens.length; i++) {
                if (tokens[i].equals("0"))
                    System.out.print(ANSI_CYAN + tokens[i] + ANSI_RESET);
                else {
                    no_of_selected++;
                    System.out.print(ANSI_BLUE + tokens[i] + ANSI_RESET);
                }
            }

            System.out.println(" " + ANSI_RED + "(" + no_of_selected + "/" + no_of_features + ")" + " " + myPop.getFittest().getFitness() + "%" + ANSI_RESET);

            // Check loop break condition
            int no = 0;
            if (solutions.size() >= iteration) {
                String test = solutions.get(solutions.size() - 1);
                for (int i = 1; i < iteration; i++)
                    if (solutions.get((solutions.size() - 1) - i).equals(test))
                        no++;

                if (no >= (iteration - 1))
                    break;
            }

            myPop = GAAlgorithm.evolvePopulation(myPop, no_of_features, weka_path, classifier, work_folder, weights, max_threads, no_of_os_instances);
        }

        // Concatenate solution into a string
        String[] tokens = solution.split("");

        String parameters_to_be_deleted = "";
        String parameters_to_stay = "";
        for (int i = 0; i < tokens.length; i++) {
            if (tokens[i].equals("0")) {
                parameters_to_be_deleted += (i+1);
                parameters_to_be_deleted += ",";
            }
            else if (tokens[i].equals("1")) {
                parameters_to_stay += (i+1);
                parameters_to_stay += ",";
            }
        }
        parameters_to_be_deleted = parameters_to_be_deleted.substring(0, parameters_to_be_deleted.length()-1); // remove the comma at the end
        parameters_to_stay = parameters_to_stay.substring(0, parameters_to_stay.length()-1); // remove the comma at the end

        // Write the concatenated string (selected feature numbers) to a file
        try {
            System.out.println();

            System.out.println(ANSI_RED + "Model path: " + ANSI_RESET + ANSI_BLUE + selected_features_file_path + ANSI_RESET);
            File file = new File(selected_features_file_path);
            BufferedWriter output_text = new BufferedWriter(new FileWriter(file, false));

            output_text.write(parameters_to_be_deleted);
            output_text.newLine();
            output_text.flush();

            output_text.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Output names of features selected to the screen
        System.out.println();
        System.out.println(ANSI_RED + "Names of the selected features by GA:" + ANSI_RESET);
        BufferedReader reader2;
        try {
            reader2 = new BufferedReader(new FileReader(filename));

            String line;
            int i = 0;
            while ((line = reader2.readLine()) != null) {
                if (!line.trim().isEmpty())
                    if (tokens[i].equals("1"))
                        System.out.println(ANSI_BLUE + line.split(",")[0] + ANSI_RESET);
                i++;
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println();
        System.out.print(ANSI_RED + "Indices of selected features by GA: " + ANSI_RESET);
        System.out.println(ANSI_BLUE + parameters_to_stay + ANSI_RESET);
        System.out.print(ANSI_RED + "Indices of removed features by GA: " + ANSI_RESET);
        System.out.println(ANSI_BLUE + parameters_to_be_deleted + ANSI_RESET);
        System.out.println();
        System.out.println(ANSI_RED + "=====================================================" + ANSI_RESET);
        System.out.println();
    }
}
