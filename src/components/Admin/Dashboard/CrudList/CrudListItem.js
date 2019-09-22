import React, {Component} from 'react';
import PropTypes from 'prop-types';
import styles from './CrudListItem.module.css';
import {Button, ButtonGroup, Card, Intent} from '@blueprintjs/core';
import {IconNames} from '@blueprintjs/icons';

class CrudListItem extends Component {
    constructor(props) {
        super(props);
        this.state = {
            expanded: false
        };

        this.getDisplayContent = this.getDisplayContent.bind(this);
    }

    getDisplayContent() {
        return this.props.display(this.props.item);
    }

    render() {
        return (
            <Card interactive={true} className={styles.container}>
                <div className={styles.bodyContainer}>
                    <div className={styles.content}>
                        {this.getDisplayContent()}
                    </div>
                    <ButtonGroup minimal={true} className={styles.actions}>
                        <Button icon={IconNames.EYE_OPEN} intent={Intent.PRIMARY} text={'View'}
                                onClick={() => this.props.onView(this.props.item)}/>
                        <Button icon={IconNames.EDIT} intent={Intent.PRIMARY} text={'Edit'}
                                onClick={() => this.props.onEdit(this.props.item)}/>
                        <Button icon={IconNames.DOCUMENT_SHARE} intent={Intent.PRIMARY}
                                text={this.props.item.draft ? "Make Public" : "Make Private"}
                                onClick={() => this.props.onTogglePrivacy(this.props.item)}/>
                    </ButtonGroup>
                    <ButtonGroup minimal={true} className={styles.delete}>
                        <Button icon={IconNames.TRASH} intent={Intent.DANGER} text={'Delete'}
                                onClick={() => this.props.onDelete(this.props.item)}/>
                    </ButtonGroup>
                </div>
            </Card>
        );
    }
}

CrudListItem.propTypes = {
    display: PropTypes.func.isRequired,
    item: PropTypes.any.isRequired,
    onEdit: PropTypes.func,
    onDelete: PropTypes.func,
    onView: PropTypes.func,
    onTogglePrivacy: PropTypes.func
};

export default CrudListItem;