import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class GAPopulation {
    GAIndividual[] individuals;
    int max_threads = 0;

    // Create a population
    public GAPopulation(int populationSize, boolean initialise, int no_of_features, String weka_path, int classifier, String work_folder, String weights, int max_threads_f, int no_of_os_instances) {
        individuals = new GAIndividual[populationSize];
        max_threads = max_threads_f;

        // Initialise population
        if (initialise) {
            // Loop and create individuals
            for (int i = 0; i < size(); i++) {
                GAIndividual newIndividual = new GAIndividual(no_of_features, weka_path, classifier, work_folder, weights, no_of_os_instances);
                newIndividual.generateIndividual();
                saveIndividual(i, newIndividual);
            }
        }
    }

    // Getters
    public GAIndividual getIndividual(int index) {
        return individuals[index];
    }

    public GAIndividual getFittest() {
/*
    	CountDownLatch latch = new CountDownLatch(size());
		ArrayList<GetFitnessThread> threads = new ArrayList<>();

		// For each individual, execute getFitness
        for (int i = 0; i < size(); i++)
        	threads.add(new GetFitnessThread(latch, individuals[i], i));

        for (int i = 0; i < size(); i++)
        	threads.get(i).start();

		try {
	        //current thread will get notified if all chidren's are done
	        // and thread will resume from wait() mode.
	        latch.await();
	    } catch (InterruptedException e) {
	        e.printStackTrace();
	    }

		Individual fittest = threads.get(0).getIndividual();

		// loop trough individuals, find maximum fitness and return that
        for (int i = 0; i < size(); i++)
        	if (fittest.getFitness(i) < threads.get(i).getIndividual().getFitness(i))
        		fittest = threads.get(i).getIndividual();

		return fittest;
*/

        ArrayList<GetFitnessThread> threads = new ArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(max_threads);

        for (int i = 0; i < size(); i++)
            threads.add(new GetFitnessThread(individuals[i]));

        for (int i = 0; i < size(); i++)
            executor.execute(threads.get(i));//calling execute method of ExecutorService

        executor.shutdown();
        while (!executor.isTerminated()) {}

        for (int i = 0; i < size(); i++)
            individuals[i] = threads.get(i).getIndividual();

        GAIndividual fittest = individuals[0];

        // loop trough individuals, find maximum fitness and return that
        for (int i = 0; i < size(); i++)
            if (fittest.getFitness() < individuals[i].getFitness())
                fittest = individuals[i];

        return fittest;
    }

    /////////////////////////
    // Get population size //
    /////////////////////////
    public int size() {
        return individuals.length;
    }

    /////////////////////
    // Save individual //
    /////////////////////
    public void saveIndividual(int index, GAIndividual indiv) {
        individuals[index] = indiv;
    }
}

/*
class GetFitnessThread extends Thread {
	private Thread t;
	private String threadName;
	private CountDownLatch latch;
	private Individual current;
	private int id;

	GetFitnessThread(CountDownLatch latch, Individual current, int id) {
		this.latch = latch;
		this.current = current;
		this.id = id;
		threadName = Integer.toString(id);
	}

	public void run() {
		@SuppressWarnings("unused")
		int temp = current.getFitness(id);
		latch.countDown();
	}

	public Individual getIndividual() {
        return current;
    }

	public void start () {
		if (t == null) {
			t = new Thread (this, threadName);
			t.start ();
		}
	}
}
*/

class GetFitnessThread extends Thread {
    private Thread t;
    private GAIndividual current;

    GetFitnessThread(GAIndividual current) {
        this.current = current;
    }

    public void run() {
        @SuppressWarnings("unused")
        double temp = current.getFitness();
    }

    public GAIndividual getIndividual() {
        return current;
    }

    public void start () {
        if (t == null) {
            t = new Thread (this);
            t.start ();
        }
    }
}
