
## Project description
The team project was implemented during the course of Operating System Design at the Technical University of Cluj-Napoca. Starting from a provided basic Operating System, having minimal functionality, the goal of the project was the implementation of the following features:
-   Implementation of Priority Based Scheduling, together with the mechanism of Priority Donation used to solve deadlocks.
-   Implementation of System Calls for Process Management and File System Access; Defining a generic handler capable of uniquely identifying the processes, threads and files the system calls work with.
-   Implementation of System Calls for dynamically allocating and releasing memory; implementation of the Page Swapping mechanism for efficient usage of the memory; implementation of Dynamically Increasing the stack of a process in case of overflow.
-   Implementation of Per-Processor Ready Lists for the scheduling task. Integration of the Affinity Mechanism for thread scheduling.

For a comprehensive documentation of how the aforementioned functionalities were implemented, please refer to the **Documentation** file.