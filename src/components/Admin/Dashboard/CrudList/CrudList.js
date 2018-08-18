import React, {Component} from 'react';
import PropTypes from 'prop-types';
import styles from './CrudList.module.css';
import {Icon} from '@blueprintjs/core';
import {IconNames} from '@blueprintjs/icons';

import classNames from 'classnames/bind'
import CrudListItem from './CrudListItem';

let cx = classNames.bind(styles);

class CrudList extends Component {
    constructor(props) {
        super(props);
        this.state = {};
    }

    render() {
        let container = cx({
            container: true
        });
        let cardClass = cx({
            item: true
        });
        return (
            <div className={container}>
                {this.props.items.map((e) => (
                    <div className={cardClass} key={e.id}>
                        <CrudListItem display={this.props.display}
                                      onEdit={this.props.onEdit}
                                      onDelete={this.props.onDelete}
                                      onView={this.props.onView}
                                      item={e}
                        />
                    </div>
                ))}
                <div className={styles.createItem} onClick={this.props.onCreate}>
                    <Icon icon={IconNames.PLUS} iconSize={25}/>
                </div>
            </div>
        );
    }
}

CrudList.propTypes = {
    display: PropTypes.func.isRequired,
    items: PropTypes.array.isRequired,
    onEdit: PropTypes.func,
    onDelete: PropTypes.func,
    onCreate: PropTypes.func,
    onView: PropTypes.func
};

export default CrudList;