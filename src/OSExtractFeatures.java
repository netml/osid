import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

public class OSExtractFeatures {
    public void extract(String packetProtocol, String tshark_attributes_input_file, String output_file, String pcap_file, String os, String tshark_bpf) {
        // Create variables
        int no_of_attributes = 0;

        // Create contents array
        ArrayList<ArrayList<String>> contents = new ArrayList<ArrayList<String>>();

        // Get attribute labels
        ArrayList<String> attribute_names = getAttributeLabels(tshark_attributes_input_file);

        // Get number of attributes
        no_of_attributes = attribute_names.size();

        ///////////////////////////////////////
        // Read packet field data into array //
        ///////////////////////////////////////
        for (int index = 0; index < attribute_names.size(); index++) { // for each column or attribute
            // Execute tshark and retrieve feature data
            if (packetProtocol == null) {
                contents.add(new ExecuteSystemCommand().execute("tshark -n -r " + pcap_file + " -Tfields -e " + attribute_names.get(index).split(",")[0] + " " + tshark_bpf, true));
                if (contents.get(contents.size()-1).size() == 0) {
                    System.out.printf(attribute_names.get(index) + " is empty!");
                    System.exit(0);
                }
            }
            else {
                contents.add(new ExecuteSystemCommand().execute("tshark -n -r " + pcap_file + " -Tfields -e " + attribute_names.get(index).split(",")[0] + " -Y " + packetProtocol + " " + tshark_bpf, true));
                if (contents.get(contents.size()-1).size() == 0) {
                    System.out.printf(attribute_names.get(index) + " is empty!");
                    System.exit(0);
                }
            }
        }

        if (attribute_names.size() != contents.size()) {
            System.out.println("Size doesn't match!!!");
            System.exit(0);
        }

        // Add classes
        ArrayList<String> classes_append = new ArrayList<String>();
        for (int j = 0; j < contents.get(0).size(); j++)
            classes_append.add(os.split("_")[0]);
        contents.add(classes_append);

//		System.out.println("Number of packets: " + contents.get(0).size());

        /////////////////////////
        // Remove null records //
        /////////////////////////
        for (int i = 0; i < contents.get(0).size(); i++) { // for each record
            int no_of_null = 0;

            for (int j = 0; j < (contents.size()-1); j++) // for each column (-1 to ignore class column)

                if (contents.get(j).get(i).equals("?"))
                    no_of_null++;

            if (no_of_null == no_of_attributes) { // remove null records
                for (int k = 0; k < contents.size(); k++) {
                    ArrayList<String> temp = contents.get(k);
                    temp.remove(i);
                    contents.set(k, temp);
                }
                i--;
            }
        }

//		System.out.println("Number of non-null packets: " + contents.get(0).size());

        //////////////////////////////////////////////////////////////////
        // Fix items in arraylist (e.g. remove commas, convert hexa...) //
        //////////////////////////////////////////////////////////////////
        for (int i = 0; i < contents.get(0).size(); i++) { // for each record
            for (int j = 0; j < (contents.size() - 1); j++) { // for each column (-1 to ignore class column)
                String item = contents.get(j).get(i);

                // Modify item
                item = item.split(",")[0]; // remove commas
                item = item.split(";")[0]; // remove semi-colons

                // Set to lower case
                item = item.toLowerCase();

                // remove whitespace
                item = item.replaceAll("\\s","");

                // convert hexa to digit
                if (attribute_names.get(j).split(",").length > 1) { // if extra information is added (,hexadecimal etc.)
                    if (attribute_names.get(j).split(",")[1].equals("hexadecimal"))
                        item = Integer.toString(hex2decimal(item));
                }

                contents.get(j).set(i, item);
            }
        }

        ////////////////////////////
        // Write examples to file //
        ////////////////////////////

        // Write the records to file
        try {
            FileWriter writer2 = new FileWriter(output_file, false);

            for (int i = 0; i < contents.get(0).size(); i++) { // for each record
                String output = "";

                // Prepare the record to be put to the file
                for (int j = 0; j < contents.size(); j++) { // for each column
                    String item = contents.get(j).get(i);
                    output = output + "," + item;
                }

                output = output.substring(1); // remove the first comma

                writer2.write(output + "\n");
                writer2.flush();
            }

            writer2.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static ArrayList<String> getAttributeLabels (String tshark_attributes_input_file) {
        ArrayList<String> attribute_names = new ArrayList<>();

        String inputFileCurrentLine = null; // holds the current line of the input file
        try {
            BufferedReader inputFile = new BufferedReader(new FileReader(tshark_attributes_input_file));

            // For each line in the input file
            while ((inputFileCurrentLine = inputFile.readLine()) != null)
                if (inputFileCurrentLine.trim().length() != 0)
                    attribute_names.add(inputFileCurrentLine);

            inputFile.close();
        } catch (IOException e2) {
            e2.printStackTrace();
        }

        return attribute_names;
    }

    public static int hex2decimal(String s) {
        String digits = "0123456789ABCDEF";
        s = s.toUpperCase();
        int val = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int d = digits.indexOf(c);
            val = 16*val + d;
        }
        return val;
    }

    public static boolean isAlphaNumeric(String s) {
        String pattern= "^[a-zA-Z0-9]*$";

        if (s.matches(pattern))
            return true;

        return false;
    }
}
