public class GAAlgorithm {
    ///////////////////
    // GA parameters //
    ///////////////////
    private static final double uniformRate = 0.5;
//    private static final double mutationRate = 0.05;
    private static final double mutationRate = 0.015;
    private static final int tournamentSize = 50;
    private static final boolean elitism = true;

    /////////////////////////
    // Evolve a population //
    /////////////////////////
    public static GAPopulation evolvePopulation(GAPopulation pop, int no_of_features, String weka_path, int classifier, String work_folder, String weights, int max_threads, int no_of_os_instances) {
        GAPopulation newPopulation = new GAPopulation(pop.size(), false, no_of_features, weka_path, classifier, work_folder, weights, max_threads, no_of_os_instances);

        // Keep our best individual
        if (elitism)
            newPopulation.saveIndividual(0, pop.getFittest());

        // Crossover population
        int elitismOffset;
        if (elitism)
            elitismOffset = 1;
        else
            elitismOffset = 0;

        // Loop over the population size and create new individuals with
        // crossover
        for (int i = elitismOffset; i < pop.size(); i++) {
            GAIndividual indiv1 = tournamentSelection(pop, no_of_features, weka_path, classifier, work_folder, weights, max_threads, no_of_os_instances);
            GAIndividual indiv2 = tournamentSelection(pop, no_of_features, weka_path, classifier, work_folder, weights, max_threads, no_of_os_instances);
            GAIndividual newIndiv = crossover(indiv1, indiv2, no_of_features, weka_path, classifier, work_folder, weights, no_of_os_instances);
            newPopulation.saveIndividual(i, newIndiv);
        }

        // Mutate population
        for (int i = elitismOffset; i < newPopulation.size(); i++)
            mutate(newPopulation.getIndividual(i));

        return newPopulation;
    }

    ///////////////////////////
    // Crossover individuals //
    ///////////////////////////
    private static GAIndividual crossover(GAIndividual indiv1, GAIndividual indiv2, int no_of_features, String weka_path, int classifier, String work_folder, String weights, int no_of_os_instances) {
        GAIndividual newSol = new GAIndividual(no_of_features, weka_path, classifier, work_folder, weights, no_of_os_instances);
        // Loop through genes
        for (int i = 0; i < indiv1.size(); i++) {
            // Crossover
            if (Math.random() <= uniformRate)
                newSol.setGene(i, indiv1.getGene(i));
            else
                newSol.setGene(i, indiv2.getGene(i));
        }
        return newSol;
    }

    //////////////////////////
    // Mutate an individual //
    //////////////////////////
    private static void mutate(GAIndividual indiv) {
        // Loop through genes
        for (int i = 0; i < indiv.size(); i++) {
            if (Math.random() <= mutationRate) {
                // Create random gene
                byte gene = (byte) Math.round(Math.random());
                indiv.setGene(i, gene);
            }
        }
    }

    //////////////////////////////////////
    // Select individuals for crossover //
    //////////////////////////////////////
    private static GAIndividual tournamentSelection(GAPopulation pop, int no_of_features, String weka_path,
                                                    int classifier, String work_folder, String weights, int max_threads, int no_of_os_instances) {
        // Create a tournament population
        GAPopulation tournament = new GAPopulation(tournamentSize, false, no_of_features, weka_path, classifier, work_folder, weights, max_threads, no_of_os_instances);

        // For each place in the tournament get a random individual
        for (int i = 0; i < tournamentSize; i++) {
            int randomId = (int) (Math.random() * pop.size());
            tournament.saveIndividual(i, pop.getIndividual(randomId));
        }

        // Get the fittest
        GAIndividual fittest = tournament.getFittest();

        return fittest;
    }
}
