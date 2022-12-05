# ADR Creation Process

1. Copy the `adr-template.md` file. Use the following filename pattern: `adr-next_number-title.md`

2. Create a draft Pull Request to get early feedback.

3. Make sure the context and solution are clear and well-documented.

4. Add an entry to a list in the [README](./README.md) file.

5. Create a Pull Request to propose a new ADR.

## ADR life cycle

ADR creation is an **iterative** process. Instead of solving all decisions in a single ADR pull Request, we MUST initially understand the problem and collect feedback by having conversations in a GitHub Issue.

1. Every ADR proposal SHOULD start with a new GitHub issue or the result of existing Issues. The Issue must contain a brief proposal summary.

2. After the motivation is validated, create a new document on the `adr-template.md`.

3. An ADR solution does not have to arrive at the `main` branch with an _accepted_ status in a single PR. If the motivation is clear and the solution is sound, we SHOULD be able to merge PRs iteratively and keep a _proposed_ status. It is preferable to have an iterative approach rather than long, not merged Pull Requests.

4. If a _proposed_ ADR is merged, the changes must be clearly documented in outstanding issues in ADR document notes or a GitHub Issue.

5. The PR SHOULD always be merged. In the case of a faulty ADR, we still prefer to merge it with a _rejected_ status. The only time the ADR SHOULD NOT be merged is if the author abandons it.

6. Merged ADRs SHOULD NOT be pruned.

### ADR status

Status has two components:

```
{CONSENSUS STATUS} {IMPLEMENTATION STATUS}
```

IMPLEMENTATION STATUS is either `Implemented` or `Not Implemented`.

#### Consensus Status

```
DRAFT -> PROPOSED -> LAST CALL yyyy-mm-dd -> ACCEPTED | REJECTED -> SUPERSEEDED by ADR-xxx
                  \        |
                   \       |
                    v      v
                     ABANDONED
```

+ `DRAFT`: [optional] an ADR, which is a work in progress, not ready for a general review. This is to present an early work and get feedback in a Draft Pull Request form.

+ `PROPOSED`: an ADR covering a complete solution architecture and still in the review - project stakeholders have not reached an agreement yet.

+ `LAST CALL <date for the last call>`: [optional] clear notice that we are close to accepting updates. Changing the status to `LAST CALL` means that social consensus (of Charon maintainers) has been reached, and we still want to give it time to let the community react or analyze.

+ `ACCEPTED`: ADR, representing a currently implemented or to-be-implemented architecture design.

+ `REJECTED`: ADR can go from PROPOSED or ACCEPTED to rejected if the consensus among project stakeholders will decide.

+ `SUPERSEEDED by ADR-xxx`: ADR, which a new ADR has superseded.

+ `ABANDONED`: the original authors no longer pursue the ADR.

## Language used in ADR

+ Write the context/background in the present tense.

+ Avoid using a first, personal form.
