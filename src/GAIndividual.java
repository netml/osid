public class GAIndividual {
    private byte[] genes;
    private double fitness = 0;
    private boolean has_run = false;
    String weka_path = null;
    int classifier = 0;
    String work_folder = null;
    String weights = null;
    int no_of_os_instances = 0;

    public GAIndividual(int no_of_features, String weka_path_f, int classifier_f, String work_folder_f, String weights_f, int no_of_os_instances_f) {
        weka_path = weka_path_f;
        classifier = classifier_f;
        work_folder = work_folder_f;
        genes = new byte[no_of_features];
        weights = weights_f;
        no_of_os_instances = no_of_os_instances_f;
    }

    // Create a random individual
    public void generateIndividual() {
        for (int i = 0; i < size(); i++) {
            byte gene = (byte) Math.round(Math.random());
            genes[i] = gene;
        }
    }

    public byte[] getGeneArray() {
        return genes;
    }

    public void setGeneArray(byte[] input) {
        this.genes = input;
    }

    public byte getGene(int index) {
        return genes[index];
    }

    public void setGene(int index, byte value) {
        genes[index] = value;
    }

    public int size() {
        return genes.length;
    }

    public double getFitness() {
        if (!has_run) {
            fitness = GAFitnessCalc.getFitness(this, weka_path, classifier, work_folder, weights, no_of_os_instances);
            has_run = true;
        }
        return fitness;
    }

    @Override
    public String toString() {
        String geneString = "";

        for (int i = 0; i < size(); i++)
            geneString += getGene(i);

        return geneString;
    }
}
