import React, {Component} from 'react';
import {NavLink, Route, Switch} from 'react-router-dom';
import {Button, ButtonGroup} from '@blueprintjs/core';
import styles from '../Dashboard.module.css';
import PropTypes from 'prop-types';
import TagList from './TagList';

class PostManager extends Component {
    render() {
        return (
            <>
                <div className={this.props.containerClassName}>
                    <ButtonGroup minimal={true}>
                        <NavLink activeClassName={styles.active} to={`${this.props.match.url}/`}>
                            <Button text={'All'}/>
                        </NavLink>
                    </ButtonGroup>
                </div>
                <Switch>
                    <Route path={`${this.props.match.url}/`} component={TagList}/>
                </Switch>
            </>
        );
    }
}

PostManager.propTypes = {
    containerClassName: PropTypes.string
};

export default PostManager;